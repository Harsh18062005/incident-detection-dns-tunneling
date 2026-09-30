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


packets = sniff(
    filter="udp port 53",
    count=5
)


dns_records = []

for packet in packets:

    record = process_packet(packet)

    if record:
        dns_records.append(record)


df = pd.DataFrame(dns_records)


if not df.empty:

    print("\nLive DNS Data:")
    print(df)

    df = extract_live_features(df)

    print("\nLive DNS Features:")
    print(df)

    df = detect_live_dns(df)

    print("\nLive DNS Detection Results:")
    print(
        df[
            [
                "source_ip",
                "query",
                "query_type",
                "is_suspicious",
                "risk_score",
                "detection_reasons"
            ]
        ]
    )

else:

    print("No DNS queries captured.")