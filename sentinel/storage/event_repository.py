"""High-throughput event repository and asynchronous SQLite persistence pipeline."""
import json
import queue
import threading
import time
from typing import Dict, List, Optional, Any
from sentinel.core.models import SecurityEvent, Incident
from sentinel.storage.database import DatabaseManager


class EventRepository:
    def __init__(self, db_manager: DatabaseManager, batch_flush_interval: float = 1.0, max_batch_size: int = 100) -> None:
        self.db_manager = db_manager
        self.batch_flush_interval = batch_flush_interval
        self.max_batch_size = max_batch_size
        self._event_queue: queue.Queue[SecurityEvent] = queue.Queue(maxsize=10000)
        self._incident_queue: queue.Queue[Incident] = queue.Queue(maxsize=1000)
        self._running = False
        self._flush_lock = threading.Lock()
        self._flush_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._flush_thread = threading.Thread(target=self._flush_worker, name="DBFlushWorker", daemon=True)
        self._flush_thread.start()

    def stop(self) -> None:
        self._running = False
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=2.0)
        self.flush()

    def save_event(self, event: SecurityEvent) -> None:
        try:
            self._event_queue.put_nowait(event)
        except queue.Full:
            self.flush()
            self._event_queue.put(event)

    def save_incident(self, incident: Incident) -> None:
        try:
            self._incident_queue.put_nowait(incident)
        except queue.Full:
            self.flush()
            self._incident_queue.put(incident)

    def _flush_worker(self) -> None:
        while self._running:
            time.sleep(self.batch_flush_interval)
            self.flush()

    def flush(self) -> None:
        with self._flush_lock:
            events: List[SecurityEvent] = []
            while not self._event_queue.empty() and len(events) < self.max_batch_size * 5:
                try:
                    events.append(self._event_queue.get_nowait())
                except queue.Empty:
                    break

            incidents: List[Incident] = []
            while not self._incident_queue.empty() and len(incidents) < self.max_batch_size:
                try:
                    incidents.append(self._incident_queue.get_nowait())
                except queue.Empty:
                    break

            if not events and not incidents:
                return

            conn = self.db_manager.get_connection()
            cursor = conn.cursor()

            try:
                all_events_map = {e.event_id: e for e in events}
                for inc in incidents:
                    for ev in inc.events:
                        if ev.event_id not in all_events_map:
                            all_events_map[ev.event_id] = ev

                if all_events_map:
                    event_rows = [
                        (
                            e.event_id, e.timestamp, e.category.value, e.severity.value,
                            e.title, e.description, e.src_ip, e.dst_ip, e.src_port,
                            e.dst_port, e.protocol, e.raw_evidence, json.dumps(e.metadata),
                        )
                        for e in all_events_map.values()
                    ]
                    cursor.executemany("""
                        INSERT OR REPLACE INTO security_events (
                            event_id, timestamp, category, severity, title, description,
                            src_ip, dst_ip, src_port, dst_port, protocol, raw_evidence, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, event_rows)

                if incidents:
                    for inc in incidents:
                        cursor.execute("""
                            INSERT OR REPLACE INTO incidents (
                                incident_id, created_at, updated_at, title, severity,
                                src_ip, target_ips_json, event_count, status, summary
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            inc.incident_id, inc.created_at, inc.updated_at, inc.title,
                            inc.severity.value, inc.src_ip, json.dumps(inc.target_ips),
                            inc.event_count, inc.status, inc.summary,
                        ))
                        for ev in inc.events:
                            cursor.execute(
                                "INSERT OR IGNORE INTO incident_event_rel (incident_id, event_id) VALUES (?, ?);",
                                (inc.incident_id, ev.event_id)
                            )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def get_recent_events(self, limit: int = 50, min_severity: Optional[str] = None) -> List[Dict[str, Any]]:
        self.flush()
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        query = "SELECT * FROM security_events"
        params = []
        if min_severity:
            query += " WHERE severity = ?"
            params.append(min_severity)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    def get_incidents(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        self.flush()
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        query = "SELECT * FROM incidents"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        self.flush()
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total_events FROM security_events;")
        total_events = cursor.fetchone()["total_events"]
        cursor.execute("SELECT COUNT(*) as total_incidents FROM incidents;")
        total_incidents = cursor.fetchone()["total_incidents"]
        cursor.execute("SELECT category, COUNT(*) as count FROM security_events GROUP BY category;")
        by_category = {r["category"]: r["count"] for r in cursor.fetchall()}
        cursor.execute("SELECT severity, COUNT(*) as count FROM security_events GROUP BY severity;")
        by_severity = {r["severity"]: r["count"] for r in cursor.fetchall()}
        cursor.execute("SELECT src_ip, COUNT(*) as count FROM security_events WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 5;")
        top_attackers = {r["src_ip"]: r["count"] for r in cursor.fetchall()}
        return {
            "total_events": total_events,
            "total_incidents": total_incidents,
            "events_by_category": by_category,
            "events_by_severity": by_severity,
            "top_attackers": top_attackers,
        }
