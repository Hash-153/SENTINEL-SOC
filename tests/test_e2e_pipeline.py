"""End-to-end integration and pipeline verification test."""
import os
import tempfile
import time
import unittest
from sentinel.core.config import SentinelConfig
from sentinel.daemon.service import SentinelService
from sentinel.capture.synthetic_generator import SyntheticAttackGenerator


class TestEndToEndPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "e2e_sentinel.db")
        self.config = SentinelConfig()
        self.config.db.db_path = self.db_path
        self.config.db.batch_flush_interval_sec = 0.05
        self.config.alerting.console_alerts = False
        self.config.alerting.structured_json_log = False
        self.service = SentinelService(self.config)
        self.service.start()

    def tearDown(self):
        self.service.stop()
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def test_full_synthetic_attack_lifecycle(self):
        for p in SyntheticAttackGenerator.generate_port_scan_packets(num_ports=20):
            self.service.ingest_packet(p)
        self.service.ingest_packet(SyntheticAttackGenerator.generate_sqli_packet())
        self.service.ingest_packet(SyntheticAttackGenerator.generate_cmd_injection_packet())
        self.service.ingest_packet(SyntheticAttackGenerator.generate_dns_tunneling_packet())
        for p in SyntheticAttackGenerator.generate_multi_stage_campaign(attacker_ip="198.51.100.88"):
            self.service.ingest_packet(p)

        time.sleep(1.0)
        self.service.event_repo.flush()

        events = self.service.event_repo.get_recent_events(limit=100)
        self.assertTrue(len(events) >= 5, f"Expected >= 5 events, got {len(events)}")

        incidents = self.service.event_repo.get_incidents()
        self.assertTrue(len(incidents) >= 1)

        stats = self.service.event_repo.get_stats()
        self.assertTrue(stats["total_events"] >= 5)


if __name__ == "__main__":
    unittest.main()
