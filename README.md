# 🛡️ DNS Tunneling Detection & Threat Intelligence Platform

[![CI Pipeline](https://github.com/Harsh18062005/incident-detection-dns-tunneling/actions/workflows/ci.yml/badge.svg)](https://github.com/Harsh18062005/incident-detection-dns-tunneling/actions/workflows/ci.yml)
[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://incident-detection-dns-tunneling.streamlit.app/)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)

An explainable, rule-based cybersecurity monitoring platform designed to detect **DNS Tunneling**, Command & Control (C2) beaconing, and data exfiltration in real time. Built with Python, Scapy, and Streamlit.

---

## 🎯 MITRE ATT&CK® Mapping

| Tactic | Technique | ID | Description |
| :--- | :--- | :--- | :--- |
| **Command and Control** | Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Adversaries communicate with C2 servers using recursive DNS resolution. |
| **Exfiltration** | Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Sensitive data is encoded into DNS labels and exfiltrated to adversary-controlled nameservers. |

---

## 🌟 Key Features

- **🔴 Live Packet Sniffer (Local NIC)**: Sniffs raw UDP/TCP Port 53 DNS queries directly from physical network interfaces using Scapy with safe timeouts.
- **⚡ Live Cloud Simulation Stream**: Enables evaluators and visitors viewing the deployed web application to generate and inspect live DNS traffic streams with one click.
- **📁 PCAP File Inspection**: Upload `.pcap` or `.pcapng` packet capture files from Wireshark for instant feature extraction and tunneling analysis.
- **📥 Incident Export**: One-click CSV reporting for both raw DNS traffic logs and categorized security incidents.
- **🏛️ Enterprise SOC Dashboard**: Corporate light-themed user interface with real-time KPI metrics, alert banners, query tables, and source IP distribution charts.

---

## 📐 Heuristic Detection Matrix

The detection engine evaluates five independent heuristic features to calculate a granular **Risk Score (0–7)**:

| Feature | Heuristic Threshold | Weight | Detection Rationale |
| :--- | :--- | :---: | :--- |
| **Domain Length** | `> 50 characters` | **+2** | Tunneling payloads require long subdomains to transfer serialized data chunks. |
| **Subdomain Count** | `≥ 2 subdomains` | **+1** | Multi-level subdomain hierarchy indicates multi-stage payload encapsulation. |
| **Shannon Entropy** | `> 3.5 bits/char` | **+2** | High entropy signifies base32/base64 encoded or encrypted data payloads. |
| **Query Frequency** | `≥ 5 queries` | **+1** | Automated C2 beaconing or rapid chunk transmissions. |
| **Query Type** | `TXT` | **+1** | TXT queries allow larger payload sizes (up to 65KB over EDNS) for bi-directional communication. |

### Severity Tiering
- **CRITICAL** (Risk Score 6–7): Active exfiltration or confirmed multi-stage tunneling payload.
- **HIGH** (Risk Score 4–5): High-confidence tunneling indicator (meets alert threshold $\ge 4$).
- **MEDIUM** (Risk Score 2–3): Anomalous query characteristics; flagged for telemetry inspection.
- **LOW** (Risk Score 0–1): Standard benign domain resolution.

---

## 🏗️ Project Architecture

```
.
├── .github/
│   └── workflows/ci.yml           # Automated GitHub Actions test pipeline
├── dashboard/
│   └── app.py                     # Streamlit SOC dashboard & live controls
├── packet_capture/
│   ├── __init__.py                # Package exports
│   └── capture_dns.py             # Scapy sniffer, simulator & PCAP processor
├── detection/
│   ├── __init__.py                # Package exports
│   ├── config.py                  # DetectionConfig & heuristic policy thresholds
│   ├── detection_engine.py        # Rule thresholds & risk score calculator
│   ├── feature_extractor.py       # Entropy, length, subdomain & frequency math
│   ├── live_feature_pipeline.py   # Feature extraction pipeline for live queries
│   ├── live_detection_pipeline.py # Detection pipeline for live queries
│   ├── alert_generator.py         # Formats explainable security alerts
│   └── feature_pipeline.py        # Offline batch dataset feature pipeline
├── tests/
│   ├── test_feature_extractor.py  # Unit tests for math & entropy extraction
│   ├── test_detection_engine.py   # Unit tests for heuristic scoring
│   └── test_packet_processor.py   # Integration tests for packet pipeline
├── data/
│   ├── dns_traffic.csv            # Synthetic baseline traffic dataset
│   ├── alerts.csv                 # Baseline generated alerts
│   ├── live_dns.csv               # Captured/simulated live DNS traffic
│   └── live_alerts.csv            # Active live alerts
├── run_dashboard.bat              # 1-click Windows desktop launcher
└── requirements.txt               # Dependencies: pandas, streamlit, scapy
```

---

## 🚀 Quickstart Guide

### 1. Installation

```bash
git clone https://github.com/Harsh18062005/incident-detection-dns-tunneling.git
cd incident-detection-dns-tunneling
pip install -r requirements.txt
```

> **Windows Users**: To capture packets locally via Scapy, ensure [Npcap](https://npcap.com/) is installed with "WinPcap API-compatible Mode" enabled.

### 2. Launching the Dashboard

- **Option A (1-Click on Windows)**: Double-click [`run_dashboard.bat`](file:///d:/3yproject/HCL/Day2/run_dashboard.bat).
- **Option B (Command Line)**:
  ```bash
  streamlit run dashboard/app.py
  ```

### 3. Run Automated Tests

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## 🌐 Live Cloud Deployment

Access the live dashboard at: **[incident-detection-dns-tunneling.streamlit.app](https://incident-detection-dns-tunneling.streamlit.app/)**

1. Switch the monitoring mode to **"Live DNS Monitoring"**.
2. Open the **"⚡ Simulate Live Stream"** tab and click **`⚡ Generate Live Traffic & Inspect`** to test live detection and alerts on the deployed site.
3. Or upload your own Wireshark capture file under **"📁 Upload PCAP File"**.

---

## ⚖️ License
Academic & Educational Project — DNS Tunneling Detection System.
