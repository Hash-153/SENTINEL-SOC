"""Unit tests for detection engines, signature matching, anomaly analysis, and correlation."""

import math
import os
import time
import unittest
from sentinel.core.config import DetectionConfig
from sentinel.core.models import (
    AttackCategory,
    AlertSeverity,
)
from sentinel.analyzers.signature_engine import SignatureEngine
from sentinel.analyzers.port_scan_detector import PortScanDetector
from sentinel.analyzers.brute_force_detector import BruteForceDetector
from sentinel.analyzers.anomaly_engine import AnomalyEngine, calculate_shannon_entropy
from sentinel.analyzers.correlation_engine import CorrelationEngine
from sentinel.capture.synthetic_generator import (
    SyntheticAttackGenerator,
    build_full_packet,
)
from sentinel.parsers.binary_decoder import decode_packet


class TestSecurityAnalyzers(unittest.TestCase):

    def setUp(self):
        self.config = DetectionConfig()
        self.sig_engine = SignatureEngine()
        self.scan_detector = PortScanDetector(self.config)
        self.brute_detector = BruteForceDetector(self.config)
        self.anomaly_engine = AnomalyEngine(self.config)
        self.correlation_engine = CorrelationEngine(correlation_window_sec=60.0)

    def test_signature_sqli_detection(self):
        pkt = SyntheticAttackGenerator.generate_sqli_packet()
        events = self.sig_engine.inspect_packet(pkt)

        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0].category, AttackCategory.SQL_INJECTION)
        self.assertIn(events[0].severity, (AlertSeverity.HIGH, AlertSeverity.CRITICAL))
        self.assertIn("UNION", events[0].description)

    def test_signature_directory_traversal(self):
        pkt = SyntheticAttackGenerator.generate_directory_traversal_packet()
        events = self.sig_engine.inspect_packet(pkt)

        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0].category, AttackCategory.DIRECTORY_TRAVERSAL)

    def test_signature_command_injection_and_ua(self):
        pkt = SyntheticAttackGenerator.generate_cmd_injection_packet()
        events = self.sig_engine.inspect_packet(pkt)

        # Should match both Command Injection and sqlmap User-Agent
        categories = {e.category for e in events}
        self.assertIn(AttackCategory.COMMAND_INJECTION, categories)
        self.assertIn(AttackCategory.SUSPICIOUS_HEADER, categories)

    def test_port_scan_vertical_detection(self):
        pkts = SyntheticAttackGenerator.generate_port_scan_packets(num_ports=20)
        detected_events = []
        for p in pkts:
            events = self.scan_detector.inspect_packet(p)
            detected_events.extend(events)

        self.assertTrue(len(detected_events) >= 1)
        self.assertEqual(detected_events[0].category, AttackCategory.PORT_SCAN)
        self.assertEqual(detected_events[0].title, "Vertical Port Scan Detected")

    def test_stealth_xmas_scan(self):
        pkt = SyntheticAttackGenerator.generate_stealth_xmas_scan()
        events = self.scan_detector.inspect_packet(pkt)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].category, AttackCategory.PORT_SCAN)
        self.assertIn("XMAS", events[0].title)

    def test_brute_force_http_401(self):
        attacker_ip = "192.168.1.200"
        server_ip = "10.0.0.5"
        base_ts = time.time()

        events = []
        for i in range(self.config.brute_force_failure_threshold + 1):
            http_401 = b"HTTP/1.1 401 Unauthorized\r\nHost: 10.0.0.5\r\n\r\nFailed login"
            # Response goes from server (src) to client (dst)
            raw = build_full_packet(server_ip, attacker_ip, src_port=80, dst_port=50000 + i, protocol="TCP", payload=http_401)
            pkt = decode_packet(raw, timestamp=base_ts + (i * 0.1))
            events.extend(self.brute_detector.inspect_packet(pkt))

        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0].category, AttackCategory.BRUTE_FORCE)
        self.assertEqual(events[0].src_ip, attacker_ip)

    def test_shannon_entropy_calculation(self):
        # Uniform bytes -> max entropy ~8.0
        random_payload = os.urandom(500)
        ent_rand = calculate_shannon_entropy(random_payload)
        self.assertTrue(ent_rand > 7.0)

        # Repeated byte -> 0.0 entropy
        zeros = b"\x00" * 500
        ent_zeros = calculate_shannon_entropy(zeros)
        self.assertEqual(ent_zeros, 0.0)

    def test_anomaly_dns_tunneling(self):
        pkt = SyntheticAttackGenerator.generate_dns_tunneling_packet()
        events = self.anomaly_engine.inspect_packet(pkt)

        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0].category, AttackCategory.DNS_ANOMALY)
        self.assertIn("DNS Tunneling", events[0].title)

    def test_multi_stage_incident_correlation(self):
        attacker = "198.51.100.99"
        campaign_pkts = SyntheticAttackGenerator.generate_multi_stage_campaign(attacker_ip=attacker)

        all_events = []
        for p in campaign_pkts:
            all_events.extend(self.sig_engine.inspect_packet(p))
            all_events.extend(self.scan_detector.inspect_packet(p))
            all_events.extend(self.anomaly_engine.inspect_packet(p))

        incident = None
        for ev in all_events:
            res = self.correlation_engine.process_event(ev)
            if res:
                incident = res

        self.assertIsNotNone(incident)
        self.assertEqual(incident.src_ip, attacker)
        self.assertIn(incident.severity, (AlertSeverity.HIGH, AlertSeverity.CRITICAL))
        self.assertTrue(incident.event_count >= 2)


if __name__ == "__main__":
    unittest.main()
