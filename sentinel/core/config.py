"""Configuration management for Sentinel NIDS/SIEM."""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DatabaseConfig:
    db_path: str = "sentinel_events.db"
    enable_wal: bool = True
    batch_flush_interval_sec: float = 1.0
    batch_max_size: int = 100
    retention_days: int = 30


@dataclass
class DetectionConfig:
    # Port Scan
    port_scan_window_sec: float = 10.0
    port_scan_threshold: int = 15
    sweep_threshold_hosts: int = 8

    # Brute Force
    brute_force_window_sec: float = 30.0
    brute_force_failure_threshold: int = 5

    # Traffic Burst & Anomaly
    baseline_window_sec: float = 60.0
    z_score_threshold: float = 3.0
    min_packets_for_baseline: int = 30

    # Payload Entropy (Shannon entropy threshold for encrypted/packed/tunneled payloads)
    entropy_high_threshold: float = 7.2
    entropy_min_payload_len: int = 64

    # Signatures
    enable_sqli_detection: bool = True
    enable_cmd_injection_detection: bool = True
    enable_traversal_detection: bool = True
    enable_xss_detection: bool = True


@dataclass
class AlertingConfig:
    min_severity: str = "LOW"
    dedup_window_sec: float = 5.0
    console_alerts: bool = True
    structured_json_log: bool = False
    alert_log_file: Optional[str] = "sentinel_alerts.log"


@dataclass
class SentinelConfig:
    db: DatabaseConfig = field(default_factory=DatabaseConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    capture_interface: Optional[str] = None
    promiscuous_mode: bool = False
    worker_threads: int = 4

    @classmethod
    def load_from_env(cls) -> "SentinelConfig":
        """Instantiate configuration with optional environment variable overrides."""
        cfg = cls()
        if os.getenv("SENTINEL_DB_PATH"):
            cfg.db.db_path = os.getenv("SENTINEL_DB_PATH", "sentinel_events.db")
        if os.getenv("SENTINEL_MIN_SEVERITY"):
            cfg.alerting.min_severity = os.getenv("SENTINEL_MIN_SEVERITY", "LOW")
        if os.getenv("SENTINEL_PORT_SCAN_THRESHOLD"):
            try:
                cfg.detection.port_scan_threshold = int(os.getenv("SENTINEL_PORT_SCAN_THRESHOLD", "15"))
            except ValueError:
                pass
        return cfg
