# 🛡️ DNS Tunneling Detection System

A rule-based, explainable cybersecurity monitoring system designed to detect **DNS Tunneling** and data exfiltration in real-time. Built with Python, Scapy, and Streamlit.

---

## 🌟 Key Features

- **🔴 Live Packet Capture (Local NIC)**: Sniffs UDP/TCP Port 53 DNS queries directly from physical network interfaces using Scapy.
- **⚡ Live Cloud Simulation Stream**: Allows anyone testing the deployed web application to generate and inspect live DNS traffic streams (benign sites + realistic tunneling attacks) with one click.
- **📁 PCAP File Inspection**: Upload `.pcap` or `.pcapng` packet capture files from Wireshark for instant feature extraction and tunneling analysis.
- **🔍 Explainable Rule-Based Detection Engine**: Calculates granular risk scores (0–7) based on:
  - **Domain Length** (high-payload subdomains)
  - **Subdomain Count** (multi-level encapsulation)
  - **Shannon Entropy** (encrypted or base32/base64-encoded strings)
  - **Query Frequency** (burst beaconing)
  - **Query Types** (TXT records used for bi-directional C2 communication)
- **📊 Interactive Streamlit Dashboard**: Dark-themed Security Operations Center (SOC) dashboard with real-time KPI metrics, alert banners, query tables, and source IP distribution charts.

---

## 🏗️ Project Architecture

```
.
├── dashboard/
│   └── app.py                     # Streamlit SOC dashboard & live controls
├── packet_capture/
│   └── capture_dns.py             # Scapy sniffer, simulator & PCAP processor
├── detection/
│   ├── detection_engine.py        # Rule thresholds & risk score calculator
│   ├── feature_extractor.py       # Entropy, length, subdomain & frequency math
│   ├── live_feature_pipeline.py   # Feature extraction pipeline for live queries
│   ├── live_detection_pipeline.py # Detection pipeline for live queries
│   ├── alert_generator.py         # Formats explainable security alerts
│   └── feature_pipeline.py        # Offline batch dataset feature pipeline
├── data/
│   ├── dns_traffic.csv            # Synthetic baseline traffic dataset
│   ├── alerts.csv                 # Baseline generated alerts
│   ├── live_dns.csv               # Captured/simulated live DNS traffic
│   └── live_alerts.csv            # Active live alerts
└── requirements.txt               # Dependencies: pandas, streamlit, scapy
```

---

## 🚀 Getting Started

### 1. Installation

Clone the repository and install requirements:

```bash
git clone https://github.com/Harsh18062005/incident-detection-dns-tunneling.git
cd incident-detection-dns-tunneling
pip install -r requirements.txt
```

> **Note for Windows users**: To capture live packets locally via Scapy, ensure [Npcap](https://npcap.com/) is installed with "WinPcap API-compatible Mode" enabled.

### 2. Run the Dashboard

```bash
streamlit run dashboard/app.py
```

### 3. Run Standalone Packet Sniffer (CLI)

```bash
python packet_capture/capture_dns.py
```

---

## 🌐 Cloud Deployment (Streamlit Community Cloud)

When deployed to Streamlit Cloud, visitors can:
1. Select **"Live DNS Monitoring"** mode.
2. Click **`⚡ Generate Live Traffic & Inspect`** under the *Simulate Live Stream* tab to test real-time detection on the cloud server.
3. Upload their own Wireshark capture files under the *Upload PCAP File* tab.

---

## ⚖️ License
Academic / Educational Project — DNS Tunneling Detection System.
