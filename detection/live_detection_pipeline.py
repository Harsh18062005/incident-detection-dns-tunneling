from detection.detection_engine import detect_dns_tunneling


def detect_live_dns(df):

    results = []

    for _, row in df.iterrows():

        is_suspicious, risk_score = detect_dns_tunneling(
            row["domain_length"],
            row["subdomain_count"],
            row["entropy"],
            row["query_frequency"],
            row["query_type_feature"]
        )

        results.append({
            "is_suspicious": is_suspicious,
            "risk_score": risk_score
        })

    df["is_suspicious"] = [
        result["is_suspicious"] for result in results
    ]

    df["risk_score"] = [
        result["risk_score"] for result in results
    ]

    return df