import pandas as pd
from scapy.all import sniff, DNS, DNSQR, IP

from detection.live_feature_pipeline import extract_live_features
from detection.live_detection_pipeline import detect_live_dns


print("Starting DNS packet capture...")

packets = sniff(
    filter="udp port 53",
    count=10
)

dns_data = []

for packet in packets:

    if (
        packet.haslayer(DNS)
        and packet.haslayer(DNSQR)
        and packet.haslayer(IP)
        and packet[DNS].qr == 0
    ):

        source_ip = packet[IP].src
        domain = packet[DNSQR].qname.decode()

        query_type = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            65: "HTTPS"
        }.get(packet[DNSQR].qtype, str(packet[DNSQR].qtype))

        dns_data.append({
            "source_ip": source_ip,
            "query": domain,
            "query_type": query_type
        })


df = pd.DataFrame(dns_data)

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
            "risk_score"
        ]
    ]
)