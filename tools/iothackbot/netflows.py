#!/usr/bin/env python3
"""
NetFlows - Network flow extraction with DNS hostname resolution.
Extracts outbound flows from pcap files and resolves hostnames using DNS lookups in the capture.
"""

import argparse
from colorama import init, Fore, Style
from .core.netflows_core import NetFlowsTool
from .core.interfaces import ConfigBuilder, OutputFormatter, ToolResult


class NetFlowsOutputFormatter(OutputFormatter):
    """Custom output formatter for network flow analysis results."""

    def _format_text(self, result: ToolResult) -> str:
        """Format network flow results as human-readable text."""
        if not result.success:
            return Fore.RED + "\n".join(result.errors) + Style.RESET_ALL

        if not result.data:
            return Fore.YELLOW + "No analysis data available." + Style.RESET_ALL

        lines = []

        for file_path, file_data in result.data.items():
            lines.append(Fore.BLUE + f"File: {file_path}" + Style.RESET_ALL)
            lines.append("=" * 60)

            source_ip = file_data.get('source_ip')
            if source_ip:
                lines.append(Fore.CYAN + f"Source IP filter: {source_ip}" + Style.RESET_ALL)

            lines.append(Fore.GREEN + f"Packets analyzed: {file_data.get('total_packets', 0)}" + Style.RESET_ALL)
            lines.append("")

            # DNS Mappings found
            dns_mappings = file_data.get('dns_mappings', {})
            if dns_mappings:
                lines.append(Fore.YELLOW + f"DNS Mappings ({len(dns_mappings)}):" + Style.RESET_ALL)
                for ip, hostname in sorted(dns_mappings.items(), key=lambda x: x[1]):
                    lines.append(f"  {ip} -> {hostname}")
                lines.append("")

            # TCP Flows
            tcp_flows = file_data.get('tcp_flows', [])
            if tcp_flows:
                lines.append(Fore.GREEN + f"TCP Flows ({len(tcp_flows)}):" + Style.RESET_ALL)
                for flow in sorted(tcp_flows, key=lambda x: (x['hostname'] or x['ip'], x['port'])):
                    if flow['hostname']:
                        lines.append(Fore.CYAN + f"  {flow['hostname']}:{flow['port']}" + Style.RESET_ALL +
                                     Fore.WHITE + f" ({flow['ip']})" + Style.RESET_ALL)
                    else:
                        lines.append(Fore.YELLOW + f"  {flow['ip']}:{flow['port']}" + Style.RESET_ALL +
                                     " (unresolved)")
                lines.append("")

            # UDP Flows
            udp_flows = file_data.get('udp_flows', [])
            if udp_flows:
                lines.append(Fore.GREEN + f"UDP Flows ({len(udp_flows)}):" + Style.RESET_ALL)
                for flow in sorted(udp_flows, key=lambda x: (x['hostname'] or x['ip'], x['port'])):
                    if flow['hostname']:
                        lines.append(Fore.CYAN + f"  {flow['hostname']}:{flow['port']}" + Style.RESET_ALL +
                                     Fore.WHITE + f" ({flow['ip']})" + Style.RESET_ALL)
                    else:
                        lines.append(Fore.YELLOW + f"  {flow['ip']}:{flow['port']}" + Style.RESET_ALL +
                                     " (unresolved)")
                lines.append("")

            # Flow Summary
            flow_summary = file_data.get('flow_summary', [])
            if flow_summary:
                lines.append(Fore.BLUE + "Flow Summary (hostname:port):" + Style.RESET_ALL)
                for flow in flow_summary:
                    lines.append(f"  {flow}")
                lines.append("")

        return "\n".join(lines)

    def _format_quiet(self, result: ToolResult) -> str:
        """Format result for quiet mode - just the flow summary."""
        if not result.success:
            return ""

        flows = []
        for file_data in result.data.values():
            flows.extend(file_data.get('flow_summary', []))

        return "\n".join(sorted(set(flows)))


def netflows():
    """Main CLI entry point for netflows."""
    parser = argparse.ArgumentParser(
        description="Extract network flows from pcap files with DNS hostname resolution.",
        epilog="Example: netflows capture.pcap --source-ip 192.168.1.100"
    )

    # Input
    parser.add_argument("pcap_files", nargs='+',
                        help="PCAP/PCAPNG file(s) to analyze")

    # Filtering options
    parser.add_argument("-s", "--source-ip", dest="source_ip",
                        help="Filter flows originating from this IP address")

    # Output options
    parser.add_argument("--format", choices=['text', 'json', 'quiet'], default='text',
                        help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")

    args = parser.parse_args()
    init()  # Initialize colorama

    # Set paths attribute for ConfigBuilder compatibility
    args.paths = args.pcap_files

    # Build configuration
    config = ConfigBuilder.from_args(args, 'netflows')

    # Add custom arguments
    config.custom_args.update({
        'source_ip': getattr(args, 'source_ip', None),
    })

    # Execute tool
    tool = NetFlowsTool()
    result = tool.run(config)

    # Format and output result
    formatter = NetFlowsOutputFormatter()
    output = formatter.format_result(result, config.output_format)
    if output:
        print(output)

    # Exit with appropriate code
    return 0 if result.success else 1


if __name__ == "__main__":
    import sys
    sys.exit(netflows())
