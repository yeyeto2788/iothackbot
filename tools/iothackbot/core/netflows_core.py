"""
Core netflows functionality - Network flow extraction and hostname resolution from pcap files.
Separated from CLI logic for automation and chaining.
"""

import os
import time
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
from .interfaces import ToolInterface, ToolConfig, ToolResult

try:
    from scapy.all import rdpcap, DNS, DNSRR, DNSQR, IP, TCP, UDP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


class NetFlowsAnalyzer:
    """Network flow analyzer with DNS resolution from pcap files."""

    def __init__(self, source_ip: Optional[str] = None):
        """
        Initialize the analyzer.

        Args:
            source_ip: Optional source IP address to filter flows from
        """
        self.source_ip = source_ip

    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """
        Analyze a pcap file to extract network flows and DNS mappings.

        Args:
            pcap_path: Path to pcap/pcapng file

        Returns:
            Analysis results dictionary with flows and DNS mappings
        """
        if not HAS_SCAPY:
            raise ImportError("Scapy is required for network flow analysis. Install with: pip install scapy")

        results = {
            'source_ip': self.source_ip,
            'dns_mappings': {},  # ip -> hostname
            'tcp_flows': [],     # list of {hostname, ip, port}
            'udp_flows': [],     # list of {hostname, ip, port}
            'total_packets': 0,
            'dns_queries': [],   # list of queried domains
        }

        # Track unique flows to avoid duplicates
        tcp_flow_set: Set[Tuple[str, int]] = set()
        udp_flow_set: Set[Tuple[str, int]] = set()

        try:
            # Read pcap file with scapy
            packets = rdpcap(pcap_path)
            results['total_packets'] = len(packets)

            # First pass: extract DNS mappings
            self._extract_dns_mappings(packets, results)

            # Second pass: extract flows
            self._extract_flows(packets, results, tcp_flow_set, udp_flow_set)

        except Exception as e:
            raise RuntimeError(f"Error analyzing pcap file: {e}")

        return results

    def _extract_dns_mappings(self, packets, results: Dict[str, Any]) -> None:
        """Extract DNS query-response mappings from packets."""
        for packet in packets:
            try:
                if packet.haslayer(DNS) and packet.haslayer(DNSRR):
                    dns_layer = packet[DNS]

                    # Only process responses (QR=1)
                    if dns_layer.qr != 1:
                        continue

                    # Get query name
                    qry_name = None
                    if dns_layer.qdcount > 0 and packet.haslayer(DNSQR):
                        qry_name = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')

                    # Process answer records by index
                    if qry_name and dns_layer.ancount > 0:
                        # Track queried domain
                        if qry_name not in results['dns_queries']:
                            results['dns_queries'].append(qry_name)

                        for i in range(dns_layer.ancount):
                            try:
                                rr = dns_layer.an[i]

                                # Check for A record (type 1)
                                if hasattr(rr, 'type') and rr.type == 1:
                                    ip = str(rr.rdata)

                                    # Map IP to the original query name (not the CNAME)
                                    if ip and ip not in results['dns_mappings']:
                                        results['dns_mappings'][ip] = qry_name

                            except (IndexError, AttributeError):
                                continue

            except Exception:
                continue

    def _extract_flows(self, packets, results: Dict[str, Any],
                       tcp_flow_set: Set[Tuple[str, int]],
                       udp_flow_set: Set[Tuple[str, int]]) -> None:
        """Extract TCP and UDP flows from packets."""
        for packet in packets:
            try:
                if not packet.haslayer(IP):
                    continue

                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                # Filter by source IP if specified
                if self.source_ip and src_ip != self.source_ip:
                    continue

                # Extract TCP flows
                if packet.haslayer(TCP):
                    dst_port = int(packet[TCP].dport)
                    flow_key = (dst_ip, dst_port)

                    if flow_key not in tcp_flow_set:
                        tcp_flow_set.add(flow_key)
                        hostname = results['dns_mappings'].get(dst_ip)
                        results['tcp_flows'].append({
                            'hostname': hostname,
                            'ip': dst_ip,
                            'port': dst_port
                        })

                # Extract UDP flows
                elif packet.haslayer(UDP):
                    dst_port = int(packet[UDP].dport)
                    flow_key = (dst_ip, dst_port)

                    if flow_key not in udp_flow_set:
                        udp_flow_set.add(flow_key)
                        hostname = results['dns_mappings'].get(dst_ip)
                        results['udp_flows'].append({
                            'hostname': hostname,
                            'ip': dst_ip,
                            'port': dst_port
                        })

            except Exception:
                continue

    def get_flow_summary(self, results: Dict[str, Any]) -> List[str]:
        """
        Generate a summary list of hostname:port flows.

        Args:
            results: Analysis results from analyze_pcap

        Returns:
            List of "hostname:port" or "ip:port" strings
        """
        flows = []

        for flow in results['tcp_flows']:
            endpoint = flow['hostname'] if flow['hostname'] else flow['ip']
            flows.append(f"{endpoint}:{flow['port']}")

        for flow in results['udp_flows']:
            endpoint = flow['hostname'] if flow['hostname'] else flow['ip']
            flows.append(f"{endpoint}:{flow['port']}")

        return sorted(set(flows))


class NetFlowsTool(ToolInterface):
    """Network flow extraction tool implementation."""

    @property
    def name(self) -> str:
        return "netflows"

    @property
    def description(self) -> str:
        return "Extract network flows from pcap files with DNS hostname resolution"

    def run(self, config: ToolConfig) -> ToolResult:
        """Execute network flow extraction."""
        start_time = time.time()

        try:
            # Extract custom arguments
            source_ip = config.custom_args.get('source_ip')

            # Initialize analyzer
            analyzer = NetFlowsAnalyzer(source_ip=source_ip)

            all_results = {}

            # Process input paths (pcap files)
            if not config.input_paths:
                return ToolResult(
                    success=False,
                    data=None,
                    errors=["No pcap file(s) provided"],
                    metadata={},
                    execution_time=time.time() - start_time
                )

            for input_path in config.input_paths:
                if not os.path.isfile(input_path):
                    return ToolResult(
                        success=False,
                        data=None,
                        errors=[f"File not found: {input_path}"],
                        metadata={},
                        execution_time=time.time() - start_time
                    )

                if not input_path.endswith(('.pcap', '.pcapng')):
                    return ToolResult(
                        success=False,
                        data=None,
                        errors=[f"Invalid file type: {input_path}. Expected .pcap or .pcapng"],
                        metadata={},
                        execution_time=time.time() - start_time
                    )

                file_results = analyzer.analyze_pcap(input_path)
                file_results['flow_summary'] = analyzer.get_flow_summary(file_results)
                all_results[input_path] = file_results

            execution_time = time.time() - start_time

            # Calculate totals
            total_tcp = sum(len(r['tcp_flows']) for r in all_results.values())
            total_udp = sum(len(r['udp_flows']) for r in all_results.values())
            total_packets = sum(r['total_packets'] for r in all_results.values())

            return ToolResult(
                success=True,
                data=all_results,
                errors=[],
                metadata={
                    'source_ip': source_ip,
                    'files_analyzed': len(all_results),
                    'total_tcp_flows': total_tcp,
                    'total_udp_flows': total_udp,
                    'total_packets': total_packets
                },
                execution_time=execution_time
            )

        except ImportError as e:
            return ToolResult(
                success=False,
                data=None,
                errors=[str(e)],
                metadata={},
                execution_time=time.time() - start_time
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data=None,
                errors=[f"Analysis failed: {str(e)}"],
                metadata={},
                execution_time=time.time() - start_time
            )
