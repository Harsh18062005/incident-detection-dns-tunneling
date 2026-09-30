def check_domain_length(domain_length):
    if domain_length > 50:
        return True
    return False


def check_subdomain_count(subdomain_count):
    if subdomain_count >= 2:
        return True
    return False


def check_entropy(entropy):
    if entropy > 3.5:
        return True
    return False


def check_query_frequency(query_frequency):
    if query_frequency >= 5:
        return True
    return False


def check_query_type(query_type):
    if query_type == "TXT":
        return True
    return False


def calculate_risk_score(
    domain_length,
    subdomain_count,
    entropy,
    query_frequency,
    query_type
):
    score = 0

    if check_domain_length(domain_length):
        score += 2

    if check_subdomain_count(subdomain_count):
        score += 1

    if check_entropy(entropy):
        score += 2

    if check_query_frequency(query_frequency):
        score += 1

    if check_query_type(query_type):
        score += 1

    return score


def get_detection_reasons(
    domain_length,
    subdomain_count,
    entropy,
    query_frequency,
    query_type
):
    reasons = []

    if check_domain_length(domain_length):
        reasons.append("Long domain")

    if check_subdomain_count(subdomain_count):
        reasons.append("Multiple subdomains")

    if check_entropy(entropy):
        reasons.append("High entropy")

    if check_query_frequency(query_frequency):
        reasons.append("High query frequency")

    if check_query_type(query_type):
        reasons.append("TXT query")

    return reasons


def detect_dns_tunneling(
    domain_length,
    subdomain_count,
    entropy,
    query_frequency,
    query_type
):
    risk_score = calculate_risk_score(
        domain_length,
        subdomain_count,
        entropy,
        query_frequency,
        query_type
    )

    if risk_score >= 4:
        return True, risk_score

    return False, risk_score