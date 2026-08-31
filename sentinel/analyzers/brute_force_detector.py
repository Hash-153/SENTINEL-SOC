"""Authentication brute-force and credential stuffing detection engine."""

from collections import defaultdict
from typing import Dict, List, Tuple
from sentinel.core.models import (
    DecodedPacket,
    SecurityEvent,
    AttackCategory,
    AlertSeverity,
)
from sentinel.core.config import DetectionConfig

AUTH_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    445: "SMB",
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRES",
    6379: "REDIS",
}


class BruteForceDetector:
    """Detects multi-attempt authentication brute force and credential stuffing attacks."""

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        # Key: (src_ip, service_or_dst_port) -> list of timestamps
        self._failure_history: Dict[Tuple[str, int], List[float]] = defaultdict(list)
        self._alert_cooldown: Dict[Tuple[str, int], float] = {}

    def inspect_packet(self, packet: DecodedPacket) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        now = packet.timestamp
        window = self.config.brute_force_window_sec

        # 1. HTTP 401 Unauthorized / 403 Forbidden check (HTTP Response)
        if packet.http and not packet.http.is_request:
            status = packet.http.status_code
            if status in (401, 403) and packet.dst_ip:
                # The attacker is the destination of the 401 response (the client who requested it)
                attacker_ip = packet.dst_ip
                port = packet.src_port or 80
                key = (attacker_ip, port)

                self._failure_history[key].append(now)
                self._failure_history[key] = [ts for ts in self._failure_history[key] if now - ts <= window]

                count = len(self._failure_history[key])
                if count >= self.config.brute_force_failure_threshold:
                    if now - self._alert_cooldown.get(key, 0) > window:
                        self._alert_cooldown[key] = now
                        events.append(
                            SecurityEvent(
                                timestamp=now,
                                category=AttackCategory.BRUTE_FORCE,
                                severity=AlertSeverity.HIGH,
                                title="HTTP Web Authentication Brute Force",
                                description=(
                                    f"Host {attacker_ip} triggered {count} HTTP 401/403 auth failures "
                                    f"within {window:.1f}s window."
                                ),
                                src_ip=attacker_ip,
                                dst_ip=packet.src_ip,
                                dst_port=port,
                                protocol="HTTP",
                                raw_evidence=f"HTTP Status: {status} across {count} attempts.",
                                metadata={"failure_count": count, "window_sec": window},
                            )
                        )

        # 2. High-Frequency SYN attempts to critical auth ports (e.g. SSH, RDP, FTP)
        if packet.tcp and packet.tcp.flag_syn and not packet.tcp.flag_ack and packet.src_ip:
            dst_port = packet.dst_port or 0
            if dst_port in AUTH_SERVICES:
                service_name = AUTH_SERVICES[dst_port]
                key = (packet.src_ip, dst_port)

                self._failure_history[key].append(now)
                self._failure_history[key] = [ts for ts in self._failure_history[key] if now - ts <= window]

                count = len(self._failure_history[key])
                if count >= self.config.brute_force_failure_threshold * 2:
                    if now - self._alert_cooldown.get(key, 0) > window:
                        self._alert_cooldown[key] = now
                        events.append(
                            SecurityEvent(
                                timestamp=now,
                                category=AttackCategory.BRUTE_FORCE,
                                severity=AlertSeverity.HIGH,
                                title=f"{service_name} Authentication Brute Force Attempt",
                                description=(
                                    f"Host {packet.src_ip} initiated {count} rapid connection attempts "
                                    f"to {service_name} (port {dst_port}) within {window:.1f}s."
                                ),
                                src_ip=packet.src_ip,
                                dst_ip=packet.dst_ip,
                                dst_port=dst_port,
                                protocol="TCP",
                                raw_evidence=f"Service: {service_name}, Attempts: {count}",
                                metadata={"service": service_name, "attempts": count},
                            )
                        )

        return events
