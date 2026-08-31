"""Alert lifecycle management, deduplication, and channel routing."""
import time
from typing import Dict, List, Tuple
from sentinel.core.models import SecurityEvent, Incident, AlertSeverity
from sentinel.core.config import AlertingConfig
from sentinel.alerting.channels import AlertChannel, ConsoleAlertChannel, JsonLogAlertChannel


class AlertManager:
    def __init__(self, config: AlertingConfig) -> None:
        self.config = config
        self.channels: List[AlertChannel] = []
        self._dedup_cache: Dict[Tuple[str, str, str], float] = {}

        if config.console_alerts:
            self.channels.append(ConsoleAlertChannel())
        if config.structured_json_log and config.alert_log_file:
            self.channels.append(JsonLogAlertChannel(config.alert_log_file))

    def add_channel(self, channel: AlertChannel) -> None:
        self.channels.append(channel)

    def _is_severity_allowed(self, severity: AlertSeverity) -> bool:
        min_sev_enum = AlertSeverity[self.config.min_severity.upper()]
        return severity.score >= min_sev_enum.score

    def handle_event(self, event: SecurityEvent) -> None:
        if not self._is_severity_allowed(event.severity):
            return

        now = event.timestamp
        dedup_key = (event.category.value, event.src_ip or "N/A", event.title)
        last_time = self._dedup_cache.get(dedup_key, 0.0)

        if now - last_time < self.config.dedup_window_sec:
            return

        self._dedup_cache[dedup_key] = now
        for channel in self.channels:
            try:
                channel.emit_event(event)
            except Exception:
                pass

    def handle_incident(self, incident: Incident) -> None:
        for channel in self.channels:
            try:
                channel.emit_incident(incident)
            except Exception:
                pass
