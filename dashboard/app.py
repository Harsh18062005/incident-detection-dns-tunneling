import streamlit as st
import pandas as pd


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="DNS Tunneling Detection",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------------------------------
# CUSTOM CSS
# ---------------------------------------------------------

st.markdown(
    """
    <style>

    .main {
        padding-top: 1rem;
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 1rem;
        padding-left: 3rem;
        padding-right: 3rem;
    }

    .metric-card {
        padding: 18px;
        border-radius: 12px;
        background-color: #111827;
        border: 1px solid #263244;
        text-align: center;
    }

    .metric-title {
        font-size: 14px;
        color: #9ca3af;
        margin-bottom: 5px;
    }

    .metric-value {
        font-size: 30px;
        font-weight: 700;
        color: #22d3ee;
    }

    .status-normal {
        padding: 10px;
        border-radius: 8px;
        background-color: #10251c;
        border: 1px solid #245b43;
        color: #7ee2ad;
        margin-bottom: 15px;
    }

    .status-alert {
        padding: 10px;
        border-radius: 8px;
        background-color: #30151a;
        border: 1px solid #71313a;
        color: #ff9b9b;
        margin-bottom: 15px;
    }

    .footer {
        margin-top: 40px;
        padding-top: 15px;
        border-top: 1px solid #263244;
        text-align: left;
        color: #8b949e;
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
# TITLE
# ---------------------------------------------------------

st.title("🛡️ DNS Tunneling Detection")

st.caption(
    "Rule-Based DNS Traffic Analysis and Explainable Alerting"
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

if mode == "Live DNS Monitoring":

    dns_file = "data/live_dns.csv"
    alerts_file = "data/live_alerts.csv"

else:

    dns_file = "data/dns_traffic.csv"
    alerts_file = "data/alerts.csv"


# ---------------------------------------------------------
# LOAD DNS DATA
# ---------------------------------------------------------

try:
    dns_df = pd.read_csv(dns_file)
except FileNotFoundError:

    st.error(
        f"DNS data file not found: `{dns_file}`"
    )

    st.stop()


# ---------------------------------------------------------
# LOAD ALERT DATA
# ---------------------------------------------------------

try:
    alerts_df = pd.read_csv(alerts_file)

except FileNotFoundError:

    alerts_df = pd.DataFrame(
        columns=[
            "source_ip",
            "query",
            "query_type",
            "risk_score",
            "alert",
            "detection_reasons"
        ]
    )


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
            <div class="metric-title">
                TOTAL DNS QUERIES
            </div>
            <div class="metric-value">
                {total_queries}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


with col2:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">
                TUNNELING ALERTS
            </div>
            <div class="metric-value">
                {total_alerts}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


with col3:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">
                SUSPICIOUS TRAFFIC
            </div>
            <div class="metric-value">
                {suspicious_percentage:.1f}%
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


with col4:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">
                HIGHEST RISK SCORE
            </div>
            <div class="metric-value">
                {highest_risk}/7
            </div>
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
            ⚠️ <b>{total_alerts}</b> suspicious DNS
            alert(s) detected.
        </div>
        """,
        unsafe_allow_html=True
    )

else:

    st.markdown(
        """
        <div class="status-normal">
            ✓ No suspicious DNS tunneling alerts detected.
        </div>
        """,
        unsafe_allow_html=True
    )


# ---------------------------------------------------------
# DNS TRAFFIC TABLE
# ---------------------------------------------------------

st.subheader("📡 DNS Traffic")

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

    st.info("No DNS traffic data available.")


# ---------------------------------------------------------
# ALERT TABLE
# ---------------------------------------------------------

st.subheader("🚨 DNS Tunneling Alerts")

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

st.subheader("📊 Suspicious Queries by Source IP")

if (
    not alerts_df.empty
    and "source_ip" in alerts_df.columns
):

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

    st.info(
        "No suspicious source IP activity to display."
    )


# ---------------------------------------------------------
# RISK SCORE DISTRIBUTION
# ---------------------------------------------------------

if (
    not alerts_df.empty
    and "risk_score" in alerts_df.columns
):

    st.subheader("📈 Risk Score Distribution")

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
        DNS Tunneling Detection System • B.Tech Project
    </div>
    """,
    unsafe_allow_html=True
)