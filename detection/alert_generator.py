import pandas as pd


def generate_alert(source_ip, query, query_type, risk_score):
    alert = {
        "source_ip": source_ip,
        "query": query,
        "query_type": query_type,
        "risk_score": risk_score,
        "alert": "DNS Tunneling Suspected"
    }

    return alert


df = pd.read_csv("data/detection_results.csv")

alerts = []

for _, row in df.iterrows():

    if row["is_suspicious"]:
        alert = generate_alert(
            row["source_ip"],
            row["query"],
            row["query_type"],
            row["risk_score"]
        )

        alerts.append(alert)


alerts_df = pd.DataFrame(alerts)

alerts_df.to_csv("data/alerts.csv", index=False)