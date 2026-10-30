import unittest
from detection.feature_extractor import (
    get_domain_length,
    get_subdomain_count,
    calculate_entropy,
    get_query_frequency,
)


class TestFeatureExtractor(unittest.TestCase):

    def test_domain_length(self):
        domain = "google.com"
        self.assertEqual(get_domain_length(domain), 10)

        long_domain = "a" * 60 + ".example.com"
        self.assertEqual(get_domain_length(long_domain), 72)

    def test_subdomain_count(self):
        self.assertEqual(get_subdomain_count("example.com"), 0)
        self.assertEqual(get_subdomain_count("sub.example.com"), 1)
        self.assertEqual(get_subdomain_count("a.b.c.example.com"), 3)

    def test_calculate_entropy(self):
        # Repetitive string should have low entropy
        low_entropy = calculate_entropy("aaaaaaa")
        self.assertEqual(low_entropy, 0.0)

        # Diverse string should have higher entropy
        high_entropy = calculate_entropy("a1b2c3d4e5f6g7h8i9j0")
        self.assertGreater(high_entropy, 3.5)

    def test_query_frequency(self):
        queries = ["google.com", "example.com", "google.com", "google.com"]
        freq = get_query_frequency(queries)
        self.assertEqual(freq["google.com"], 3)
        self.assertEqual(freq["example.com"], 1)


if __name__ == "__main__":
    unittest.main()
