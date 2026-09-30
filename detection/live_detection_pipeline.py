from detection.detection_engine import (
    detect_dns_tunneling,
    get_detection_reasons
)


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

        reasons = get_detection_reasons(
            row["domain_length"],
            row["subdomain_count"],
            row["entropy"],
            row["query_frequency"],
            row["query_type_feature"]
        )

        status = "SUSPICIOUS" if is_suspicious else "NORMAL"

        results.append({
            "is_suspicious": is_suspicious,
            "risk_score": risk_score,
            "status": status,
            "detection_reasons": ", ".join(reasons)
        })

    df["is_suspicious"] = [
        result["is_suspicious"] for result in results
    ]

    df["risk_score"] = [
        result["risk_score"] for result in results
    ]

    df["status"] = [
        result["status"] for result in results
    ]

    df["detection_reasons"] = [
        result["detection_reasons"] for result in results
    ]

    return df