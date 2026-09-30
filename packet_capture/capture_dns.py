from scapy.all import sniff, DNS, DNSQR, IP, IPv6
import pandas as pd

from detection.live_feature_pipeline import extract_live_features
from detection.live_detection_pipeline import detect_live_dns
from detection.alert_generator import generate_alerts_from_dataframe


print("Starting DNS packet capture...")


def process_packet(packet):

    if (
        packet.haslayer(DNS)
        and packet.haslayer(DNSQR)
        and (
            packet.haslayer(IP)
            or packet.haslayer(IPv6)
        )
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

        # Get source IP address
        if packet.haslayer(IP):

            source_ip = packet[IP].src

        else:

            source_ip = packet[IPv6].src

        return {
            "source_ip": source_ip,
            "query": query,
            "query_type": query_type
        }

    return None


# ============================================================
# CAPTURE DNS PACKETS
# ============================================================

packets = sniff(
    filter="udp port 53 or tcp port 53",
    count=50
)


# ============================================================
# PROCESS CAPTURED PACKETS
# ============================================================

dns_records = []

for packet in packets:

    record = process_packet(packet)

    if record:
        dns_records.append(record)


# ============================================================
# PROCESS DNS DATA
# ============================================================

df = pd.DataFrame(dns_records)


if not df.empty:

    # Display live DNS data
    print("\nLive DNS Data:")
    print(df)

    # Save ALL live DNS queries
    df.to_csv(
        "data/live_dns.csv",
        index=False
    )

    # ========================================================
    # FEATURE EXTRACTION
    # ========================================================

    df = extract_live_features(df)

    print("\nLive DNS Features:")
    print(df)

    # ========================================================
    # DNS DETECTION
    # ========================================================

    df = detect_live_dns(df)

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

    # ========================================================
    # ALERT GENERATION
    # ========================================================

    live_alerts = generate_alerts_from_dataframe(df)

    # Save suspicious live alerts
    live_alerts.to_csv(
        "data/live_alerts.csv",
        index=False
    )

    print("\nLive DNS Alerts:")

    if not live_alerts.empty:

        print(
            live_alerts.to_string(index=False)
        )

        print(
            f"\nLive alerts saved: {len(live_alerts)}"
        )

    else:

        print("No suspicious DNS alerts generated.")
        print("Live alerts saved: 0")


else:

    # ========================================================
    # NO DNS PACKETS CAPTURED
    # ========================================================

    empty_live_dns = pd.DataFrame(
        columns=[
            "source_ip",
            "query",
            "query_type"
        ]
    )

    empty_live_dns.to_csv(
        "data/live_dns.csv",
        index=False
    )

    empty_alerts = pd.DataFrame(
        columns=[
            "source_ip",
            "query",
            "query_type",
            "risk_score",
            "alert",
            "detection_reasons"
        ]
    )

    empty_alerts.to_csv(
        "data/live_alerts.csv",
        index=False
    )

    print("No DNS queries captured.")
    print("Live alerts saved: 0")