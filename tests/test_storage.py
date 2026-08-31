"""Unit tests for SQLite database management, batch persistence, and retention."""
import os
import tempfile
import unittest
from sentinel.storage.database import DatabaseManager
from sentinel.storage.event_repository import EventRepository
from sentinel.storage.retention_policy import RetentionPolicy
from sentinel.core.models import SecurityEvent, Incident, AttackCategory, AlertSeverity


class TestStorageLayer(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_sentinel.db")
        self.db_manager = DatabaseManager(self.db_path, enable_wal=True)
        self.repo = EventRepository(self.db_manager, batch_flush_interval=0.1, max_batch_size=10)
        self.repo.start()

    def tearDown(self):
        self.repo.stop()
        self.db_manager.close()
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def test_save_and_query_events(self):
        ev1 = SecurityEvent(
            category=AttackCategory.SQL_INJECTION,
            severity=AlertSeverity.HIGH,
            title="SQLi Test",
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            protocol="HTTP",
            raw_evidence="UNION SELECT",
        )
        self.repo.save_event(ev1)
        self.repo.flush()
        events = self.repo.get_recent_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], ev1.event_id)

    def test_save_and_query_incident_with_events(self):
        ev1 = SecurityEvent(category=AttackCategory.PORT_SCAN, severity=AlertSeverity.MEDIUM, title="Scan", src_ip="1.2.3.4")
        ev2 = SecurityEvent(category=AttackCategory.COMMAND_INJECTION, severity=AlertSeverity.CRITICAL, title="Cmd", src_ip="1.2.3.4")
        self.repo.save_event(ev1)
        self.repo.save_event(ev2)
        inc = Incident(title="Multi-stage", severity=AlertSeverity.CRITICAL, src_ip="1.2.3.4", target_ips=["10.0.0.1"], event_count=2, events=[ev1, ev2])
        self.repo.save_incident(inc)
        self.repo.flush()
        incidents = self.repo.get_incidents(limit=5)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["severity"], "CRITICAL")

    def test_stats_aggregation(self):
        self.repo.save_event(SecurityEvent(category=AttackCategory.SQL_INJECTION, severity=AlertSeverity.HIGH, src_ip="10.1.1.1"))
        self.repo.save_event(SecurityEvent(category=AttackCategory.PORT_SCAN, severity=AlertSeverity.LOW, src_ip="10.1.1.2"))
        self.repo.flush()
        stats = self.repo.get_stats()
        self.assertEqual(stats["total_events"], 2)


if __name__ == "__main__":
    unittest.main()
