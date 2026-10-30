import os
import io
import random
import string
import pandas as pd
from scapy.all import sniff, rdpcap, DNS, DNSQR, IP, IPv6

from detection.live_feature_pipeline import extract_live_features
from detection.live_detection_pipeline import detect_live_dns
from detection.alert_generator import generate_alerts_from_dataframe

# Base and data directory paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
LIVE_DNS_FILE = os.path.join(DATA_DIR, "live_dns.csv")
LIVE_ALERTS_FILE = os.path.join(DATA_DIR, "live_alerts.csv")

QUERY_TYPE_MAP = {
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


def process_packet(packet):
    """
    Extract DNS query details from a captured Scapy packet.
    """
    try:
        if (
            packet.haslayer(DNS)
            and packet.haslayer(DNSQR)
            and (packet.haslayer(IP) or packet.haslayer(IPv6))
            and packet[DNS].qr == 0
        ):
            raw_qname = packet[DNSQR].qname
            if isinstance(raw_qname, bytes):
                query = raw_qname.decode(errors="replace")
            else:
                query = str(raw_qname)

            query_type = QUERY_TYPE_MAP.get(
                packet[DNSQR].qtype,
                str(packet[DNSQR].qtype)
            )

            if packet.haslayer(IP):
                source_ip = packet[IP].src
            else:
                source_ip = packet[IPv6].src

            return {
                "source_ip": source_ip,
                "query": query,
                "query_type": query_type
            }
    except Exception:
        return None

    return None


def process_dns_dataframe(df, save_to_disk=True):
    """
    Takes a raw DataFrame with ['source_ip', 'query', 'query_type'].
    Runs feature extraction, detection engine, and alert generation.
    Returns (processed_df, alerts_df).
    """
    if df is None or df.empty:
        empty_dns = pd.DataFrame(columns=[
            "source_ip", "query", "query_type", "domain_length",
            "subdomain_count", "entropy", "query_frequency", "risk_score", "status"
        ])
        empty_alerts = pd.DataFrame(columns=[
            "source_ip", "query", "query_type", "risk_score", "alert", "detection_reasons"
        ])
        if save_to_disk:
            os.makedirs(DATA_DIR, exist_ok=True)
            empty_dns.to_csv(LIVE_DNS_FILE, index=False)
            empty_alerts.to_csv(LIVE_ALERTS_FILE, index=False)
        return empty_dns, empty_alerts

    # Extract features
    df = extract_live_features(df)

    # Detect DNS tunneling
    df = detect_live_dns(df)

    # Generate alerts
    alerts_df = generate_alerts_from_dataframe(df)

    if save_to_disk:
        os.makedirs(DATA_DIR, exist_ok=True)
        df.to_csv(LIVE_DNS_FILE, index=False)
        alerts_df.to_csv(LIVE_ALERTS_FILE, index=False)

    return df, alerts_df


def capture_live_packets(count=30, timeout=8, iface=None):
    """
    Sniffs live DNS traffic using Scapy with a safe timeout.
    Returns:
        (success: bool, records_or_error: list or str)
    """
    try:
        sniff_kwargs = {
            "filter": "udp port 53 or tcp port 53",
            "count": count,
            "timeout": timeout
        }
        if iface:
            sniff_kwargs["iface"] = iface

        packets = sniff(**sniff_kwargs)

        dns_records = []
        for packet in packets:
            record = process_packet(packet)
            if record:
                dns_records.append(record)

        return True, dns_records
    except PermissionError:
        return False, "Permission denied: Raw packet sniffing requires Administrator/root privileges or Npcap."
    except Exception as e:
        return False, f"Packet capture error: {str(e)}"


def parse_pcap(pcap_source):
    """
    Parse DNS packets from a PCAP file or file-like buffer.
    Returns (success: bool, records_or_error: list or str).
    """
    try:
        if isinstance(pcap_source, (str, os.PathLike)):
            packets = rdpcap(pcap_source)
        else:
            buffer = io.BytesIO(pcap_source.read() if hasattr(pcap_source, "read") else pcap_source)
            packets = rdpcap(buffer)

        dns_records = []
        for packet in packets:
            record = process_packet(packet)
            if record:
                dns_records.append(record)

        return True, dns_records
    except Exception as e:
        return False, f"Failed to parse PCAP file: {str(e)}"


def generate_simulated_traffic(count=25, attack_ratio=0.3):
    """
    Generates realistic live DNS traffic (benign + tunneling attacks).
    Allows visitors on deployed cloud apps to test live detection on demand.
    """
    benign_domains = [
        "google.com", "youtube.com", "github.com", "microsoft.com",
        "amazon.com", "facebook.com", "wikipedia.org", "stackoverflow.com",
        "api.slack.com", "cdn.cloudflare.net", "netflix.com", "linkedin.com",
        "reddit.com", "docs.python.org", "streamlit.io", "openai.com"
    ]

    records = []
    num_attacks = max(1, int(count * attack_ratio))
    num_normal = count - num_attacks

    chars = string.ascii_lowercase + string.digits

    # Normal queries
    for _ in range(num_normal):
        domain = random.choice(benign_domains)
        if random.random() < 0.3:
            sub = random.choice(["api", "cdn", "assets", "auth", "static", "login"])
            domain = f"{sub}.{domain}"
        records.append({
            "source_ip": f"192.168.1.{random.randint(2, 50)}",
            "query": domain,
            "query_type": random.choice(["A", "AAAA", "CNAME", "MX"])
        })

    # Suspicious tunneling queries
    for _ in range(num_attacks):
        sub_len = random.randint(38, 65)
        encoded_data = "".join(random.choice(chars) for _ in range(sub_len))
        tunnel_type = random.choice(["txt_exfil", "multi_subdomain", "c2_beacon"])

        if tunnel_type == "txt_exfil":
            query = f"{encoded_data}.exfil-c2.net"
            qtype = "TXT"
        elif tunnel_type == "multi_subdomain":
            part1 = "".join(random.choice(chars) for _ in range(20))
            part2 = "".join(random.choice(chars) for _ in range(25))
            query = f"{part1}.{part2}.data-tunnel.org"
            qtype = random.choice(["TXT", "A"])
        else:
            query = f"beacon-{encoded_data[:30]}.covert-channel.io"
            qtype = "TXT"

        records.append({
            "source_ip": f"192.168.1.{random.randint(2, 10)}",
            "query": query,
            "query_type": qtype
        })

    random.shuffle(records)
    return records


def run_standalone_capture(count=50, timeout=15):
    """CLI capture runner matching original capture_dns behavior with timeouts."""
    print(f"Starting DNS packet capture (count={count}, timeout={timeout}s)...")
    success, records_or_err = capture_live_packets(count=count, timeout=timeout)

    if not success:
        print(f"[Error] {records_or_err}")
        return

    records = records_or_err
    df = pd.DataFrame(records)

    if not df.empty:
        print(f"\nCaptured {len(df)} DNS queries.")
        processed_df, alerts_df = process_dns_dataframe(df, save_to_disk=True)
        print("\nLive DNS Detection Results:")
        print(
            processed_df[
                ["query", "status", "risk_score", "detection_reasons"]
            ].to_string(index=False)
        )
        print(f"\nLive alerts saved: {len(alerts_df)}")
    else:
        print("No DNS packets captured within timeout.")
        process_dns_dataframe(pd.DataFrame(), save_to_disk=True)


if __name__ == "__main__":
    run_standalone_capture()
