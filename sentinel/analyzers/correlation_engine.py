"""Complex Event Processing (CEP) and Multi-Stage Incident Correlation Engine."""

import time
from collections import defaultdict
from typing import Dict, List, Optional
from sentinel.core.models import (
    SecurityEvent,
    Incident,
    AlertSeverity,
    AttackCategory,
)


class CorrelationEngine:
    """Correlates disparate atomic security events into high-fidelity actionable security incidents."""

    def __init__(self, correlation_window_sec: float = 60.0) -> None:
        self.correlation_window_sec = correlation_window_sec
        # Key: src_ip -> List of SecurityEvent
        self._ip_event_window: Dict[str, List[SecurityEvent]] = defaultdict(list)
        # Key: src_ip -> Active Incident ID
        self._active_incidents: Dict[str, Incident] = {}

    def process_event(self, event: SecurityEvent) -> Optional[Incident]:
        """Process a security event and evaluate whether it warrants a synthesized Incident."""
        if not event.src_ip:
            return None

        src_ip = event.src_ip
        now = event.timestamp

        # Add event to window
        self._ip_event_window[src_ip].append(event)
        # Prune events older than the window
        self._ip_event_window[src_ip] = [
            e for e in self._ip_event_window[src_ip] if now - e.timestamp <= self.correlation_window_sec
        ]

        events = self._ip_event_window[src_ip]
        if len(events) < 2:
            return None

        # Check distinct categories
        distinct_categories = {e.category for e in events}
        total_score = sum(e.severity.score for e in events)

        # Multi-stage attack condition:
        # e.g., Recon (Port Scan/UA) + Exploit (SQLi/CMDi) OR Exploit + Exfil (Entropy/DNS)
        is_multi_stage = len(distinct_categories) >= 2
        is_high_volume_attack = len(events) >= 5 or total_score >= 150

        if not (is_multi_stage or is_high_volume_attack):
            return None

        # Determine escalated incident severity
        if total_score >= 200 or AttackCategory.COMMAND_INJECTION in distinct_categories:
            inc_severity = AlertSeverity.CRITICAL
        elif total_score >= 100 or is_multi_stage:
            inc_severity = AlertSeverity.HIGH
        else:
            inc_severity = AlertSeverity.MEDIUM

        # Distinct target IPs
        target_ips = sorted(list({e.dst_ip for e in events if e.dst_ip}))

        category_names = ", ".join(c.value for c in distinct_categories)
        summary = (
            f"Multi-stage malicious activity detected from {src_ip}. "
            f"Observed {len(events)} security events across {len(distinct_categories)} vectors ({category_names}) "
            f"targeting {len(target_ips)} host(s)."
        )

        title = f"Multi-Stage Security Incident: {src_ip}"
        if is_multi_stage:
            title = f"Coordinated Multi-Vector Attack from {src_ip}"

        # Update existing incident or create a new one
        if src_ip in self._active_incidents:
            incident = self._active_incidents[src_ip]
            incident.updated_at = now
            incident.severity = inc_severity
            incident.target_ips = target_ips
            incident.event_count = len(events)
            incident.events = list(events)
            incident.summary = summary
            incident.title = title
        else:
            incident = Incident(
                created_at=now,
                updated_at=now,
                title=title,
                severity=inc_severity,
                src_ip=src_ip,
                target_ips=target_ips,
                event_count=len(events),
                events=list(events),
                status="ACTIVE",
                summary=summary,
            )
            self._active_incidents[src_ip] = incident

        return incident
