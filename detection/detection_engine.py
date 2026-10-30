"""
Rule-Based DNS Tunneling Detection Engine.
Evaluates individual DNS query telemetry against configurable heuristic thresholds.
"""

from detection.config import DEFAULT_CONFIG, DetectionConfig


def check_domain_length(domain_length, config: DetectionConfig = DEFAULT_CONFIG):
    return domain_length > config.DOMAIN_LENGTH_THRESHOLD


def check_subdomain_count(subdomain_count, config: DetectionConfig = DEFAULT_CONFIG):
    return subdomain_count >= config.SUBDOMAIN_COUNT_THRESHOLD


def check_entropy(entropy, config: DetectionConfig = DEFAULT_CONFIG):
    return entropy > config.ENTROPY_THRESHOLD


def check_query_frequency(query_frequency, config: DetectionConfig = DEFAULT_CONFIG):
    return query_frequency >= config.QUERY_FREQUENCY_THRESHOLD


def check_query_type(query_type, config: DetectionConfig = DEFAULT_CONFIG):
    return query_type in config.SUSPICIOUS_QUERY_TYPES


def calculate_risk_score(
    domain_length,
    subdomain_count,
    entropy,
    query_frequency,
    query_type,
    config: DetectionConfig = DEFAULT_CONFIG
):
    score = 0

    if check_domain_length(domain_length, config):
        score += config.WEIGHT_DOMAIN_LENGTH

    if check_subdomain_count(subdomain_count, config):
        score += config.WEIGHT_SUBDOMAIN_COUNT

    if check_entropy(entropy, config):
        score += config.WEIGHT_ENTROPY

    if check_query_frequency(query_frequency, config):
        score += config.WEIGHT_QUERY_FREQUENCY

    if check_query_type(query_type, config):
        score += config.WEIGHT_QUERY_TYPE

    return min(score, config.MAX_RISK_SCORE)


def get_detection_reasons(
    domain_length,
    subdomain_count,
    entropy,
    query_frequency,
    query_type,
    config: DetectionConfig = DEFAULT_CONFIG
):
    reasons = []

    if check_domain_length(domain_length, config):
        reasons.append("Long domain")

    if check_subdomain_count(subdomain_count, config):
        reasons.append("Multiple subdomains")

    if check_entropy(entropy, config):
        reasons.append("High entropy")

    if check_query_frequency(query_frequency, config):
        reasons.append("High query frequency")

    if check_query_type(query_type, config):
        reasons.append(f"{query_type} query")

    return reasons


def detect_dns_tunneling(
    domain_length,
    subdomain_count,
    entropy,
    query_frequency,
    query_type,
    config: DetectionConfig = DEFAULT_CONFIG
):
    risk_score = calculate_risk_score(
        domain_length,
        subdomain_count,
        entropy,
        query_frequency,
        query_type,
        config
    )

    is_suspicious = risk_score >= config.ALERT_RISK_THRESHOLD
    return is_suspicious, risk_score
