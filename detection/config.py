"""
Detection Engine Configuration and Rule Thresholds.
Defines tunable parameters and heuristic thresholds for DNS tunneling identification.
"""

from dataclasses import dataclass
from typing import List


@dataclass
class DetectionConfig:
    # Heuristic Thresholds
    DOMAIN_LENGTH_THRESHOLD: int = 50
    SUBDOMAIN_COUNT_THRESHOLD: int = 2
    ENTROPY_THRESHOLD: float = 3.5
    QUERY_FREQUENCY_THRESHOLD: int = 5
    SUSPICIOUS_QUERY_TYPES: tuple = ("TXT",)

    # Risk Weights
    WEIGHT_DOMAIN_LENGTH: int = 2
    WEIGHT_SUBDOMAIN_COUNT: int = 1
    WEIGHT_ENTROPY: int = 2
    WEIGHT_QUERY_FREQUENCY: int = 1
    WEIGHT_QUERY_TYPE: int = 1

    # Decision Threshold
    ALERT_RISK_THRESHOLD: int = 4
    MAX_RISK_SCORE: int = 7


# Default global instance
DEFAULT_CONFIG = DetectionConfig()
