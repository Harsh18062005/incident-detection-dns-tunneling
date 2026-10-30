import unittest
import pandas as pd
from packet_capture.capture_dns import (
    generate_simulated_traffic,
    process_dns_dataframe,
)


class TestPacketProcessor(unittest.TestCase):

    def test_empty_dataframe_processing(self):
        empty_df = pd.DataFrame()
        processed_df, alerts_df = process_dns_dataframe(empty_df, save_to_disk=False)
        self.assertTrue(processed_df.empty)
        self.assertTrue(alerts_df.empty)
        self.assertIn("risk_score", processed_df.columns)
        self.assertIn("alert", alerts_df.columns)

    def test_simulated_traffic_generation(self):
        records = generate_simulated_traffic(count=20, attack_ratio=0.3)
        self.assertEqual(len(records), 20)
        for rec in records:
            self.assertIn("source_ip", rec)
            self.assertIn("query", rec)
            self.assertIn("query_type", rec)

    def test_end_to_end_pipeline(self):
        records = generate_simulated_traffic(count=30, attack_ratio=0.4)
        raw_df = pd.DataFrame(records)
        processed_df, alerts_df = process_dns_dataframe(raw_df, save_to_disk=False)

        self.assertEqual(len(processed_df), 30)
        self.assertIn("risk_score", processed_df.columns)
        self.assertIn("status", processed_df.columns)
        self.assertIn("entropy", processed_df.columns)
        self.assertGreater(len(alerts_df), 0)


if __name__ == "__main__":
    unittest.main()
