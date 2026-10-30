"""
Packet Capture & Telemetry Processing Package.
Provides live Scapy sniffer, PCAP inspection, and simulation generation.
"""

from packet_capture.capture_dns import (
    capture_live_packets,
    generate_simulated_traffic,
    parse_pcap,
    process_dns_dataframe,
    process_packet,
)

__all__ = [
    "capture_live_packets",
    "generate_simulated_traffic",
    "parse_pcap",
    "process_dns_dataframe",
    "process_packet",
]
