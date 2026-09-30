import streamlit as st
import pandas as pd


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="DNS Tunneling Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
<style>

/* Main application container */
[data-testid="stAppViewContainer"] {
    width: 100%;
}

/* Main content area */
[data-testid="stMainBlockContainer"] {
    max-width: 100%;
    padding-left: 3rem;
    padding-right: 3rem;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* Fallback for older Streamlit versions */
.block-container {
    max-width: 100%;
    padding-left: 3rem;
    padding-right: 3rem;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* Metrics */
div[data-testid="stMetric"] {
    border: 1px solid rgba(128, 128, 128, 0.25);
    border-radius: 12px;
    padding: 1rem;
    min-height: 105px;
    background: rgba(128, 128, 128, 0.06);
}

/* Metric values */
div[data-testid="stMetricValue"] {
    font-size: 1.8rem;
    font-weight: 700;
}

/* Dataframes */
div[data-testid="stDataFrame"] {
    width: 100%;
    border-radius: 10px;
}

/* Radio buttons */
div[data-testid="stRadio"] {
    margin-bottom: 1rem;
}

/* Mobile */
@media (max-width: 768px) {

    [data-testid="stMainBlockContainer"],
    .block-container {
        padding-left: 1rem;
        padding-right: 1rem;
        padding-top: 1rem;
    }

    div[data-testid="stMetric"] {
        min-height: 90px;
    }

    div[data-testid="stMetricValue"] {
        font-size: 1.4rem;
    }

}

</style>
""",
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ DNS Tunneling Detection Dashboard")

st.caption(
    "Real-time DNS traffic monitoring, risk analysis and "
    "suspicious DNS tunneling detection"
)


# ============================================================
# MONITORING MODE
# ============================================================

st.subheader("Monitoring Mode")

mode = st.radio(
    "Select monitoring mode",
    [
        "Live DNS Monitoring",
        "Synthetic Dataset Testing"
    ],
    horizontal=True,
    label_visibility="collapsed"
)


# ============================================================
# LIVE DNS MONITORING
# ============================================================

if mode == "Live DNS Monitoring":

    st.header("📡 Live DNS Monitoring")

    # --------------------------------------------------------
    # LOAD LIVE DNS DATA
    # --------------------------------------------------------

    try:
        live_dns = pd.read_csv(
            "data/live_dns.csv"
        )
    except (FileNotFoundError, pd.errors.EmptyDataError):
        live_dns = pd.DataFrame()

    # --------------------------------------------------------
    # LOAD LIVE ALERTS
    # --------------------------------------------------------

    try:
        live_alerts = pd.read_csv(
            "data/live_alerts.csv"
        )
    except (FileNotFoundError, pd.errors.EmptyDataError):
        live_alerts = pd.DataFrame()

    # --------------------------------------------------------
    # CALCULATE METRICS
    # --------------------------------------------------------

    total_queries = len(live_dns)
    total_alerts = len(live_alerts)

    if total_queries > 0:

        suspicious_percentage = (
            total_alerts / total_queries
        ) * 100

    else:

        suspicious_percentage = 0

    if not live_alerts.empty:

        highest_risk = live_alerts["risk_score"].max()

    else:

        highest_risk = 0

    # --------------------------------------------------------
    # METRIC CARDS
    # --------------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total DNS Queries",
        total_queries
    )

    col2.metric(
        "Tunneling Alerts",
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

    # --------------------------------------------------------
    # STATUS
    # --------------------------------------------------------

    if total_queries == 0:

        st.info(
            "No DNS traffic was captured in the latest "
            "monitoring session."
        )

    elif total_alerts == 0:

        st.success(
            "No suspicious DNS traffic detected in the "
            "latest live capture."
        )

    else:

        st.warning(
            f"{total_alerts} suspicious DNS query(s) "
            "detected in the latest capture."
        )

    # --------------------------------------------------------
    # LIVE DNS QUERIES
    # --------------------------------------------------------

    st.subheader("🌐 Live DNS Queries")

    if not live_dns.empty:

        display_live_dns = live_dns[
            [
                "source_ip",
                "query",
                "query_type"
            ]
        ]

        st.dataframe(
            display_live_dns,
            use_container_width=True,
            hide_index=True,
            height=350
        )

    else:

        st.info(
            "No live DNS queries available."
        )

    # --------------------------------------------------------
    # LIVE ALERTS
    # --------------------------------------------------------

    if not live_alerts.empty:

        st.subheader(
            "🚨 DNS Tunneling Alerts"
        )

        display_alerts = live_alerts[
            [
                "source_ip",
                "query",
                "query_type",
                "risk_score",
                "alert",
                "detection_reasons"
            ]
        ]

        st.dataframe(
            display_alerts,
            use_container_width=True,
            hide_index=True,
            height=280
        )

        # ----------------------------------------------------
        # SOURCE IP CHART
        # ----------------------------------------------------

        st.subheader(
            "📊 Suspicious Queries by Source IP"
        )

        live_ip_counts = (
            live_alerts["source_ip"]
            .value_counts()
            .rename("Alerts")
        )

        st.bar_chart(
            live_ip_counts,
            use_container_width=True
        )


# ============================================================
# SYNTHETIC DATASET TESTING
# ============================================================

else:

    st.header("🧪 Synthetic Dataset Testing")

    # --------------------------------------------------------
    # LOAD SYNTHETIC DNS DATA
    # --------------------------------------------------------

    try:

        dns_traffic = pd.read_csv(
            "data/dns_traffic.csv"
        )

    except (FileNotFoundError, pd.errors.EmptyDataError):

        dns_traffic = pd.DataFrame()

    # --------------------------------------------------------
    # LOAD SYNTHETIC ALERTS
    # --------------------------------------------------------

    try:

        alerts = pd.read_csv(
            "data/alerts.csv"
        )

    except (FileNotFoundError, pd.errors.EmptyDataError):

        alerts = pd.DataFrame()

    # --------------------------------------------------------
    # CALCULATE METRICS
    # --------------------------------------------------------

    total_queries = len(dns_traffic)
    total_alerts = len(alerts)

    if total_queries > 0:

        suspicious_percentage = (
            total_alerts / total_queries
        ) * 100

    else:

        suspicious_percentage = 0

    if not alerts.empty:

        highest_risk = alerts["risk_score"].max()

    else:

        highest_risk = 0

    # --------------------------------------------------------
    # METRIC CARDS
    # --------------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total DNS Queries",
        total_queries
    )

    col2.metric(
        "Tunneling Alerts",
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

    # --------------------------------------------------------
    # SYNTHETIC DNS TRAFFIC
    # --------------------------------------------------------

    st.subheader(
        "📄 Synthetic DNS Traffic"
    )

    if not dns_traffic.empty:

        st.dataframe(
            dns_traffic,
            use_container_width=True,
            hide_index=True,
            height=400
        )

    else:

        st.info(
            "No synthetic DNS traffic available."
        )

    # --------------------------------------------------------
    # SYNTHETIC ALERTS
    # --------------------------------------------------------

    st.subheader(
        "🚨 Detected DNS Tunneling Alerts"
    )

    if not alerts.empty:

        display_alerts = alerts[
            [
                "source_ip",
                "query",
                "query_type",
                "risk_score",
                "alert",
                "detection_reasons"
            ]
        ]

        st.dataframe(
            display_alerts,
            use_container_width=True,
            hide_index=True,
            height=350
        )

        # ----------------------------------------------------
        # SOURCE IP CHART
        # ----------------------------------------------------

        st.subheader(
            "📊 Suspicious Queries by Source IP"
        )

        ip_counts = (
            alerts["source_ip"]
            .value_counts()
            .rename("Alerts")
        )

        st.bar_chart(
            ip_counts,
            use_container_width=True
        )

    else:

        st.info(
            "No suspicious DNS traffic detected."
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "DNS Tunneling Detection System • HCL Project"
)