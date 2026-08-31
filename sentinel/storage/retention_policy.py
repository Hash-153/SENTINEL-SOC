"""Data retention, database pruning, and storage vacuum policies."""
import time
from sentinel.storage.database import DatabaseManager


class RetentionPolicy:
    def __init__(self, db_manager: DatabaseManager, retention_days: int = 30) -> None:
        self.db_manager = db_manager
        self.retention_days = retention_days

    def purge_stale_records(self) -> int:
        cutoff_ts = time.time() - (self.retention_days * 86400)
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_events WHERE timestamp < ?;", (cutoff_ts,))
        deleted_count = cursor.rowcount
        cursor.execute("DELETE FROM incidents WHERE updated_at < ? AND status = 'RESOLVED';", (cutoff_ts,))
        conn.commit()
        return deleted_count

    def optimize_database(self) -> None:
        conn = self.db_manager.get_connection()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        conn.commit()
