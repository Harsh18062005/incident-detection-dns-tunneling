import pandas as pd

from detection.detection_engine import get_detection_reasons


def generate_alert(
    source_ip,
    query,
    query_type,
    risk_score,
    detection_reasons
):
    alert = {
        "source_ip": source_ip,
        "query": query,
        "query_type": query_type,
        "risk_score": risk_score,
        "alert": "DNS Tunneling Suspected",
        "detection_reasons": ", ".join(detection_reasons)
    }

    return alert


# Load detection results
df = pd.read_csv("data/detection_results.csv")

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


# Create alerts DataFrame
alerts_df = pd.DataFrame(alerts)

# Save alerts
alerts_df.to_csv("data/alerts.csv", index=False)

print("Alerts generated:", len(alerts_df))
print("\nGenerated Alerts:")
print(alerts_df.to_string(index=False))