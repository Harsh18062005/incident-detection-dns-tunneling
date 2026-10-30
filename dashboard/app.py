import os
import sys
from pathlib import Path
import streamlit as st
import pandas as pd

# Add project root to sys.path so modules can be imported when running from any directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from packet_capture.capture_dns import (
    capture_live_packets,
    generate_simulated_traffic,
    parse_pcap,
    process_dns_dataframe
)


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="DNS Tunneling Detection | Enterprise SOC",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------------------------------
# CORPORATE LIGHT THEME CUSTOM CSS
# ---------------------------------------------------------

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }

    .main {
        background-color: #f8fafc;
    }

    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2rem;
        padding-left: 3rem;
        padding-right: 3rem;
    }

    .enterprise-header {
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 16px;
        margin-bottom: 22px;
    }

    .enterprise-badge {
        display: inline-block;
        padding: 3px 9px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        background-color: #eff6ff;
        color: #1d4ed8;
        border: 1px solid #bfdbfe;
        margin-bottom: 8px;
    }

    .metric-card {
        padding: 18px 14px;
        border-radius: 8px;
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.04);
        text-align: center;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
    }

    .metric-card:hover {
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.07);
        border-color: #cbd5e1;
    }

    .metric-title {
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        color: #64748b;
        margin-bottom: 6px;
    }

    .metric-value {
        font-size: 28px;
        font-weight: 700;
        color: #0f172a;
        line-height: 1.2;
    }

    .metric-value-alert {
        color: #b91c1c;
    }

    .status-normal {
        padding: 12px 18px;
        border-radius: 8px;
        background-color: #f0fdf4;
        border: 1px solid #bbf7d0;
        color: #166534;
        font-weight: 500;
        font-size: 14px;
        margin-bottom: 20px;
    }

    .status-alert {
        padding: 12px 18px;
        border-radius: 8px;
        background-color: #fef2f2;
        border: 1px solid #fecaca;
        color: #991b1b;
        font-weight: 500;
        font-size: 14px;
        margin-bottom: 20px;
    }

    .footer {
        margin-top: 48px;
        padding-top: 16px;
        border-top: 1px solid #e2e8f0;
        text-align: left;
        color: #64748b;
        font-size: 12px;
    }

    @media (max-width: 900px) {
        .block-container {
            padding-left: 1rem;
            padding-right: 1rem;
        }
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ---------------------------------------------------------
# CORPORATE HEADER
# ---------------------------------------------------------

st.markdown(
    """
    <div class="enterprise-header">
        <span class="enterprise-badge">Enterprise SOC</span>
        <h1 style="margin: 0; font-size: 26px; font-weight: 700; color: #0f172a; letter-spacing: -0.02em;">
            🛡️ DNS Tunneling Detection & Threat Intelligence
        </h1>
        <p style="margin: 4px 0 0 0; font-size: 13px; color: #64748b;">
            Rule-Based DNS Traffic Inspection, Payload Entropy Analysis & Explainable Alerting
        </p>
    </div>
    """,
    unsafe_allow_html=True
)


# ---------------------------------------------------------
# MONITORING MODE
# ---------------------------------------------------------

mode = st.radio(
    "Monitoring Mode",
    [
        "Live DNS Monitoring",
        "Synthetic Dataset Testing"
    ],
    horizontal=True
)


# ---------------------------------------------------------
# FILE PATHS
# ---------------------------------------------------------

DATA_DIR = os.path.join(str(PROJECT_ROOT), "data")

if mode == "Live DNS Monitoring":
    dns_file = os.path.join(DATA_DIR, "live_dns.csv")
    alerts_file = os.path.join(DATA_DIR, "live_alerts.csv")
else:
    dns_file = os.path.join(DATA_DIR, "dns_traffic.csv")
    alerts_file = os.path.join(DATA_DIR, "alerts.csv")


# ---------------------------------------------------------
# LIVE CAPTURE & CONTROLS (Only in Live DNS Monitoring mode)
# ---------------------------------------------------------

if mode == "Live DNS Monitoring":

    with st.expander("📡 Live Packet Capture & Traffic Controls", expanded=True):

        tab1, tab2, tab3 = st.tabs([
            "🔴 Live Capture (Local NIC)",
            "⚡ Simulate Live Stream (Cloud & Demo)",
            "📁 Upload PCAP File"
        ])

        with tab1:
            st.markdown(
                "<span style='color: #64748b; font-size: 13px;'>"
                "Sniffs live DNS packets (UDP/TCP port 53) directly from the local system's network interface using Scapy. "
                "(Requires local machine execution with Administrator/Npcap permissions)."
                "</span>",
                unsafe_allow_html=True
            )
            col_l1, col_l2 = st.columns([1, 1])
            with col_l1:
                packet_count = st.slider(
                    "Packet Count",
                    min_value=10,
                    max_value=100,
                    value=30,
                    step=10,
                    key="live_pkt_cnt"
                )
            with col_l2:
                timeout_sec = st.slider(
                    "Timeout (seconds)",
                    min_value=3,
                    max_value=20,
                    value=8,
                    step=1,
                    key="live_timeout"
                )

            if st.button("▶ Start Live Capture", type="primary", key="btn_start_sniff"):
                with st.spinner(f"Sniffing network interface for {packet_count} DNS packets (timeout: {timeout_sec}s)..."):
                    success, result = capture_live_packets(count=packet_count, timeout=timeout_sec)

                    if not success:
                        st.warning(
                            f"⚠️ {result}\n\n"
                            "💡 **Cloud Deployment Note**: Web browsers running on client systems cannot directly "
                            "grant raw network card sniffing access to remote web apps. "
                            "Please use the **'⚡ Simulate Live Stream'** tab to test live detection on the deployed site!"
                        )
                    elif len(result) == 0:
                        st.info(
                            "ℹ️ No DNS queries detected during the timeout period. "
                            "Try opening a website in another browser tab to generate DNS traffic, or increase the timeout."
                        )
                    else:
                        raw_df = pd.DataFrame(result)
                        processed_df, alerts_res = process_dns_dataframe(raw_df, save_to_disk=True)
                        st.session_state["live_dns_df"] = processed_df
                        st.session_state["live_alerts_df"] = alerts_res
                        st.success(f"✓ Captured and analyzed {len(processed_df)} live DNS queries ({len(alerts_res)} alerts)!")
                        st.rerun()

        with tab2:
            st.markdown(
                "<span style='color: #64748b; font-size: 13px;'>"
                "Generates a realistic live stream of DNS queries (normal enterprise websites + DNS tunneling attack patterns) "
                "and passes them directly into the live detection pipeline. "
                "<b>Guaranteed to work 100% on deployed cloud environments.</b>"
                "</span>",
                unsafe_allow_html=True
            )
            col_s1, col_s2 = st.columns([1, 1])
            with col_s1:
                sim_count = st.slider(
                    "Number of Live Queries",
                    min_value=10,
                    max_value=60,
                    value=25,
                    step=5,
                    key="sim_cnt"
                )
            with col_s2:
                attack_pct = st.slider(
                    "Tunneling Attack Ratio (%)",
                    min_value=10,
                    max_value=50,
                    value=28,
                    step=5,
                    key="sim_ratio"
                )

            if st.button("⚡ Generate Live Traffic & Inspect", type="primary", key="btn_gen_traffic"):
                with st.spinner("Generating live DNS queries and analyzing with detection engine..."):
                    sim_records = generate_simulated_traffic(
                        count=sim_count,
                        attack_ratio=attack_pct / 100.0
                    )
                    raw_df = pd.DataFrame(sim_records)
                    processed_df, alerts_res = process_dns_dataframe(raw_df, save_to_disk=True)
                    st.session_state["live_dns_df"] = processed_df
                    st.session_state["live_alerts_df"] = alerts_res
                    st.success(f"✓ Generated & analyzed {len(processed_df)} live DNS queries ({len(alerts_res)} suspicious alerts)!")
                    st.rerun()

        with tab3:
            st.markdown(
                "<span style='color: #64748b; font-size: 13px;'>"
                "Upload a <code>.pcap</code> or <code>.pcapng</code> file captured from Wireshark on your system "
                "to inspect your actual network packets on this deployed dashboard."
                "</span>",
                unsafe_allow_html=True
            )
            uploaded_pcap = st.file_uploader(
                "Upload PCAP capture",
                type=["pcap", "pcapng"],
                key="pcap_upload"
            )

            if uploaded_pcap is not None:
                if st.button("🔍 Analyze PCAP Traffic", key="btn_parse_pcap"):
                    with st.spinner("Parsing PCAP and extracting DNS features..."):
                        success, result = parse_pcap(uploaded_pcap)
                        if not success:
                            st.error(f"❌ {result}")
                        elif len(result) == 0:
                            st.warning("⚠️ No DNS queries found in this PCAP file.")
                        else:
                            raw_df = pd.DataFrame(result)
                            processed_df, alerts_res = process_dns_dataframe(raw_df, save_to_disk=True)
                            st.session_state["live_dns_df"] = processed_df
                            st.session_state["live_alerts_df"] = alerts_res
                            st.success(f"✓ Successfully processed {len(processed_df)} DNS queries from PCAP ({len(alerts_res)} alerts)!")
                            st.rerun()

        # Reset button
        col_r1, _ = st.columns([1, 4])
        with col_r1:
            if st.button("🗑️ Reset Live Data", key="btn_reset_live"):
                empty_dns, empty_alerts = process_dns_dataframe(pd.DataFrame(), save_to_disk=True)
                st.session_state["live_dns_df"] = empty_dns
                st.session_state["live_alerts_df"] = empty_alerts
                st.info("Live data reset to clean baseline.")
                st.rerun()


# ---------------------------------------------------------
# LOAD DNS & ALERT DATA
# ---------------------------------------------------------

if mode == "Live DNS Monitoring":
    if "live_dns_df" in st.session_state and "live_alerts_df" in st.session_state:
        dns_df = st.session_state["live_dns_df"]
        alerts_df = st.session_state["live_alerts_df"]
    else:
        try:
            dns_df = pd.read_csv(dns_file)
        except (FileNotFoundError, pd.errors.EmptyDataError):
            dns_df = pd.DataFrame(columns=[
                "source_ip", "query", "query_type", "domain_length",
                "subdomain_count", "entropy", "query_frequency", "risk_score", "status"
            ])

        try:
            alerts_df = pd.read_csv(alerts_file)
        except (FileNotFoundError, pd.errors.EmptyDataError):
            alerts_df = pd.DataFrame(columns=[
                "source_ip", "query", "query_type", "risk_score", "alert", "detection_reasons"
            ])
else:
    try:
        dns_df = pd.read_csv(dns_file)
    except FileNotFoundError:
        st.error(f"DNS data file not found: `{dns_file}`")
        st.stop()

    try:
        alerts_df = pd.read_csv(alerts_file)
    except FileNotFoundError:
        alerts_df = pd.DataFrame(columns=[
            "source_ip", "query", "query_type", "risk_score", "alert", "detection_reasons"
        ])


# ---------------------------------------------------------
# BASIC DATA CLEANING
# ---------------------------------------------------------

if "risk_score" in alerts_df.columns:
    alerts_df["risk_score"] = pd.to_numeric(
        alerts_df["risk_score"],
        errors="coerce"
    ).fillna(0)

if "risk_score" in dns_df.columns:
    dns_df["risk_score"] = pd.to_numeric(
        dns_df["risk_score"],
        errors="coerce"
    ).fillna(0)


# ---------------------------------------------------------
# METRICS
# ---------------------------------------------------------

total_queries = len(dns_df)
total_alerts = len(alerts_df)

if total_queries > 0:
    suspicious_percentage = (
        total_alerts / total_queries
    ) * 100
else:
    suspicious_percentage = 0


if not alerts_df.empty and "risk_score" in alerts_df.columns:
    highest_risk = int(
        alerts_df["risk_score"].max()
    )
else:
    highest_risk = 0


# ---------------------------------------------------------
# KPI CARDS
# ---------------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">TOTAL DNS QUERIES</div>
            <div class="metric-value">{total_queries}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col2:
    alert_class = "metric-value-alert" if total_alerts > 0 else "metric-value"
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">TUNNELING ALERTS</div>
            <div class="metric-value {alert_class}">{total_alerts}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col3:
    pct_class = "metric-value-alert" if suspicious_percentage > 0 else "metric-value"
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">SUSPICIOUS TRAFFIC</div>
            <div class="metric-value {pct_class}">{suspicious_percentage:.1f}%</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col4:
    risk_class = "metric-value-alert" if highest_risk >= 4 else "metric-value"
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">HIGHEST RISK SCORE</div>
            <div class="metric-value {risk_class}">{highest_risk}/7</div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ---------------------------------------------------------
# STATUS
# ---------------------------------------------------------

if total_alerts > 0:
    st.markdown(
        f"""
        <div class="status-alert">
            ⚠️ <b>{total_alerts}</b> suspicious DNS tunneling alert(s) detected. Investigation recommended.
        </div>
        """,
        unsafe_allow_html=True
    )
else:
    st.markdown(
        """
        <div class="status-normal">
            ✓ Normal DNS activity &bull; No active tunneling threats detected.
        </div>
        """,
        unsafe_allow_html=True
    )


# ---------------------------------------------------------
# DNS TRAFFIC TABLE
# ---------------------------------------------------------

st.subheader("📡 DNS Traffic Log")

if not dns_df.empty:
    display_columns = [
        column
        for column in [
            "source_ip",
            "query",
            "query_type",
            "domain_length",
            "subdomain_count",
            "entropy",
            "query_frequency",
            "risk_score",
            "status"
        ]
        if column in dns_df.columns
    ]

    if display_columns:
        st.dataframe(
            dns_df[display_columns],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.dataframe(
            dns_df,
            use_container_width=True,
            hide_index=True
        )
else:
    st.info("No DNS traffic data available. Use the controls above to start live capture or generate live traffic.")


# ---------------------------------------------------------
# ALERT TABLE
# ---------------------------------------------------------

st.subheader("🚨 Incident Alerts")

if not alerts_df.empty:
    alert_columns = [
        column
        for column in [
            "source_ip",
            "query",
            "query_type",
            "risk_score",
            "alert",
            "detection_reasons"
        ]
        if column in alerts_df.columns
    ]

    st.dataframe(
        alerts_df[alert_columns],
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No suspicious DNS alerts available.")


# ---------------------------------------------------------
# SOURCE IP ANALYSIS
# ---------------------------------------------------------

st.subheader("📊 Threat Distribution by Source IP")

if not alerts_df.empty and "source_ip" in alerts_df.columns:
    source_counts = (
        alerts_df["source_ip"]
        .value_counts()
        .rename("Suspicious Queries")
    )
    st.bar_chart(
        source_counts,
        use_container_width=True
    )
else:
    st.info("No suspicious source IP activity to display.")


# ---------------------------------------------------------
# RISK SCORE DISTRIBUTION
# ---------------------------------------------------------

if not alerts_df.empty and "risk_score" in alerts_df.columns:
    st.subheader("📈 Risk Score Breakdown")
    risk_counts = (
        alerts_df["risk_score"]
        .value_counts()
        .sort_index()
        .rename("Alerts")
    )
    st.bar_chart(
        risk_counts,
        use_container_width=True
    )


# ---------------------------------------------------------
# FOOTER
# ---------------------------------------------------------

st.markdown(
    """
    <div class="footer">
        DNS Tunneling Detection System &bull; Enterprise Threat Monitoring & SOC Analytics
    </div>
    """,
    unsafe_allow_html=True
)
