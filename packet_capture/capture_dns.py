from scapy.all import sniff, DNS, DNSQR, IP
import pandas as pd

from detection.live_feature_pipeline import extract_live_features
from detection.live_detection_pipeline import detect_live_dns


print("Starting DNS packet capture...")


def process_packet(packet):

    if (
        packet.haslayer(DNS)
        and packet.haslayer(DNSQR)
        and packet.haslayer(IP)
        and packet[DNS].qr == 0
    ):

        query = packet[DNSQR].qname.decode()

        query_type_map = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            65: "HTTPS"
        }

        query_type = query_type_map.get(
            packet[DNSQR].qtype,
            str(packet[DNSQR].qtype)
        )

        return {
            "source_ip": packet[IP].src,
            "query": query,
            "query_type": query_type
        }

    return None


# Capture DNS packets
packets = sniff(
    filter="udp port 53",
    count=5
)


# Process captured packets
dns_records = []

for packet in packets:

    record = process_packet(packet)

    if record:
        dns_records.append(record)


# Convert captured data to DataFrame
df = pd.DataFrame(dns_records)


if not df.empty:

    # Display live DNS data
    print("\nLive DNS Data:")
    print(df)

    # Extract features
    df = extract_live_features(df)

    print("\nLive DNS Features:")
    print(df)

    # Run detection
    df = detect_live_dns(df)

    # Display clear detection results
    print("\nLive DNS Detection Results:")

    print(
        df[
            [
                "query",
                "status",
                "risk_score",
                "detection_reasons"
            ]
        ].to_string(index=False)
    )

else:

    print("No DNS queries captured.")