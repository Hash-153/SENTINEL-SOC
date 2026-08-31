"""Thread-safe SQLite database schema management and connection pool."""
import sqlite3
import threading
from typing import Optional


class DatabaseManager:
    def __init__(self, db_path: str = "sentinel_events.db", enable_wal: bool = True) -> None:
        self.db_path = db_path
        self.enable_wal = enable_wal
        self._local = threading.local()
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "connection") or self._local.connection is None:
            conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            if self.enable_wal:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.connection = conn
        return self._local.connection

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        if self.enable_wal:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")

        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                raw_evidence TEXT,
                metadata_json TEXT
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT,
                target_ips_json TEXT,
                event_count INTEGER NOT NULL,
                status TEXT NOT NULL,
                summary TEXT
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incident_event_rel (
                incident_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (incident_id, event_id),
                FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
                FOREIGN KEY (event_id) REFERENCES security_events(event_id) ON DELETE CASCADE
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events (timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON security_events (src_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events (severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_cat ON security_events (category);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents (updated_at);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents (src_ip);")
        conn.commit()
        conn.close()

    def close(self) -> None:
        if hasattr(self._local, "connection") and self._local.connection:
            try:
                self._local.connection.close()
            except Exception:
                pass
            self._local.connection = None
