import unittest
from detection.detection_engine import (
    check_domain_length,
    check_subdomain_count,
    check_entropy,
    check_query_frequency,
    check_query_type,
    calculate_risk_score,
    get_detection_reasons,
    detect_dns_tunneling,
)
from detection.config import DEFAULT_CONFIG


class TestDetectionEngine(unittest.TestCase):

    def test_heuristic_checks(self):
        self.assertTrue(check_domain_length(55))
        self.assertFalse(check_domain_length(30))

        self.assertTrue(check_subdomain_count(2))
        self.assertFalse(check_subdomain_count(1))

        self.assertTrue(check_entropy(3.8))
        self.assertFalse(check_entropy(2.5))

        self.assertTrue(check_query_frequency(5))
        self.assertFalse(check_query_frequency(3))

        self.assertTrue(check_query_type("TXT"))
        self.assertFalse(check_query_type("A"))

    def test_benign_query_risk(self):
        # Benign: length 10, subdomains 0, entropy 2.5, frequency 1, type A
        score = calculate_risk_score(
            domain_length=10,
            subdomain_count=0,
            entropy=2.5,
            query_frequency=1,
            query_type="A"
        )
        self.assertEqual(score, 0)

        is_suspicious, calculated_score = detect_dns_tunneling(
            domain_length=10,
            subdomain_count=0,
            entropy=2.5,
            query_frequency=1,
            query_type="A"
        )
        self.assertFalse(is_suspicious)
        self.assertEqual(calculated_score, 0)

    def test_tunneling_query_detection(self):
        # Suspicious: length 65, subdomains 3, entropy 4.2, frequency 6, type TXT
        # Score calculation: 2 (length) + 1 (subdomains) + 2 (entropy) + 1 (freq) + 1 (TXT) = 7
        score = calculate_risk_score(
            domain_length=65,
            subdomain_count=3,
            entropy=4.2,
            query_frequency=6,
            query_type="TXT"
        )
        self.assertEqual(score, 7)

        is_suspicious, calculated_score = detect_dns_tunneling(
            domain_length=65,
            subdomain_count=3,
            entropy=4.2,
            query_frequency=6,
            query_type="TXT"
        )
        self.assertTrue(is_suspicious)
        self.assertEqual(calculated_score, 7)

    def test_detection_reasons(self):
        reasons = get_detection_reasons(
            domain_length=60,
            subdomain_count=2,
            entropy=4.0,
            query_frequency=5,
            query_type="TXT"
        )
        self.assertIn("Long domain", reasons)
        self.assertIn("Multiple subdomains", reasons)
        self.assertIn("High entropy", reasons)
        self.assertIn("High query frequency", reasons)
        self.assertIn("TXT query", reasons)


if __name__ == "__main__":
    unittest.main()
