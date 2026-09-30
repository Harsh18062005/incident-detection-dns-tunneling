import streamlit as st
import pandas as pd


# Dashboard title
st.title("DNS Tunneling Detection Dashboard")


# Load project data
dns_traffic = pd.read_csv("data/dns_traffic.csv")
alerts = pd.read_csv("data/alerts.csv")

# Load live alerts if available
try:
    live_alerts = pd.read_csv("data/live_alerts.csv")
except FileNotFoundError:
    live_alerts = pd.DataFrame()


# ============================================================
# SYNTHETIC DATASET SECTION
# ============================================================

st.header("Synthetic DNS Detection Results")


# Calculate dashboard metrics
total_queries = len(dns_traffic)
total_alerts = len(alerts)

suspicious_percentage = (
    total_alerts / total_queries
) * 100

if not alerts.empty:
    highest_risk = alerts["risk_score"].max()
else:
    highest_risk = 0


# Display metrics
col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total DNS Queries",
    total_queries
)

col2.metric(
    "DNS Tunneling Alerts",
    total_alerts
)

col3.metric(
    "Suspicious Traffic",
    f"{suspicious_percentage:.1f}%"
)

col4.metric(
    "Highest Risk Score",
    highest_risk
)


# Display synthetic alerts
st.subheader("Detected DNS Tunneling Alerts")

if not alerts.empty:

    st.dataframe(
        alerts[
            [
                "source_ip",
                "query",
                "query_type",
                "risk_score",
                "alert",
                "detection_reasons"
            ]
        ],
        use_container_width=True
    )

else:

    st.info("No suspicious DNS traffic detected.")


# Count alerts by source IP
if not alerts.empty:

    ip_counts = alerts["source_ip"].value_counts()

    st.subheader("Suspicious Queries by Source IP")

    st.bar_chart(ip_counts)


# ============================================================
# LIVE DNS MONITORING SECTION
# ============================================================

st.divider()

st.header("Live DNS Monitoring")

if live_alerts.empty:

    st.success(
        "No suspicious DNS traffic detected in the latest live capture."
    )

    st.metric(
        "Live DNS Alerts",
        0
    )

else:

    live_alert_count = len(live_alerts)
    live_highest_risk = live_alerts["risk_score"].max()

    col1, col2 = st.columns(2)

    col1.metric(
        "Live DNS Alerts",
        live_alert_count
    )

    col2.metric(
        "Highest Live Risk Score",
        live_highest_risk
    )

    st.subheader("Live DNS Tunneling Alerts")

    st.dataframe(
        live_alerts[
            [
                "source_ip",
                "query",
                "query_type",
                "risk_score",
                "alert",
                "detection_reasons"
            ]
        ],
        use_container_width=True
    )

    # Count live alerts by source IP
    live_ip_counts = live_alerts["source_ip"].value_counts()

    st.subheader("Live Suspicious Queries by Source IP")

    st.bar_chart(live_ip_counts)