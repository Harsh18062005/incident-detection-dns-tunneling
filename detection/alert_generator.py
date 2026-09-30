import pandas as pd

from detection.detection_engine import get_detection_reasons


def generate_alert(
    source_ip,
    query,
    query_type,
    risk_score,
    detection_reasons
):
    return {
        "source_ip": source_ip,
        "query": query,
        "query_type": query_type,
        "risk_score": risk_score,
        "alert": "DNS Tunneling Suspected",
        "detection_reasons": ", ".join(detection_reasons)
    }


def generate_alerts_from_dataframe(df):

    alerts = []

    for _, row in df.iterrows():

        if row["is_suspicious"]:

            reasons = get_detection_reasons(
                row["domain_length"],
                row["subdomain_count"],
                row["entropy"],
                row["query_frequency"],
                row["query_type_feature"]
            )

            alert = generate_alert(
                row["source_ip"],
                row["query"],
                row["query_type"],
                row["risk_score"],
                reasons
            )

            alerts.append(alert)

    # Always return the expected columns,
    # even when there are no suspicious alerts.
    return pd.DataFrame(
        alerts,
        columns=[
            "source_ip",
            "query",
            "query_type",
            "risk_score",
            "alert",
            "detection_reasons"
        ]
    )


def generate_synthetic_alerts():

    df = pd.read_csv("data/detection_results.csv")

    alerts_df = generate_alerts_from_dataframe(df)

    alerts_df.to_csv(
        "data/alerts.csv",
        index=False
    )

    print("Alerts generated:", len(alerts_df))

    print("\nGenerated Alerts:")

    if not alerts_df.empty:
        print(alerts_df.to_string(index=False))
    else:
        print("No suspicious DNS traffic detected.")


if __name__ == "__main__":
    generate_synthetic_alerts()