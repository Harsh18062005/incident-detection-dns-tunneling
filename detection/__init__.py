"""
DNS Tunneling Detection Package.
Provides feature extraction, heuristic detection engine, and security alerting.
"""

from detection.config import DetectionConfig, DEFAULT_CONFIG
from detection.detection_engine import (
    detect_dns_tunneling,
    calculate_risk_score,
    get_detection_reasons,
)
from detection.feature_extractor import (
    get_domain_length,
    get_subdomain_count,
    calculate_entropy,
    get_query_frequency,
)

__version__ = "1.0.0"
__all__ = [
    "DetectionConfig",
    "DEFAULT_CONFIG",
    "detect_dns_tunneling",
    "calculate_risk_score",
    "get_detection_reasons",
    "get_domain_length",
    "get_subdomain_count",
    "calculate_entropy",
    "get_query_frequency",
]
