"""Sliding-window temporal port scan and network sweep detector."""

import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple
from sentinel.core.models import (
    DecodedPacket,
    SecurityEvent,
    AttackCategory,
    AlertSeverity,
)
from sentinel.core.config import DetectionConfig


class PortScanDetector:
    """Detects horizontal port scans, vertical network sweeps, and stealth TCP scans."""

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        # Key: (src_ip, dst_ip) -> List of (timestamp, dst_port)
        self._port_history: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)
        # Key: (src_ip, dst_port) -> List of (timestamp, dst_ip)
        self._sweep_history: Dict[Tuple[str, int], List[Tuple[float, str]]] = defaultdict(list)
        # Key: (src_ip, scan_type) -> last_alert_time
        self._alert_cooldown: Dict[Tuple[str, str], float] = {}

    def inspect_packet(self, packet: DecodedPacket) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        if not packet.src_ip or not packet.dst_ip or not packet.tcp:
            return events

        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        dst_port = packet.dst_port or 0
        now = packet.timestamp
        window = self.config.port_scan_window_sec

        # 1. Check Stealth TCP flag combinations
        stealth_event = self._check_stealth_flags(packet)
        if stealth_event:
            events.append(stealth_event)

        # 2. Track Vertical Port Scan (single host, multiple ports)
        target_pair = (src_ip, dst_ip)
        self._port_history[target_pair].append((now, dst_port))
        # Prune old records
        self._port_history[target_pair] = [
            (ts, p) for (ts, p) in self._port_history[target_pair] if now - ts <= window
        ]

        distinct_ports = {p for (_, p) in self._port_history[target_pair]}
        if len(distinct_ports) >= self.config.port_scan_threshold:
            cooldown_key = (src_ip, f"PORT_SCAN_{dst_ip}")
            if now - self._alert_cooldown.get(cooldown_key, 0) > window:
                self._alert_cooldown[cooldown_key] = now
                events.append(
                    SecurityEvent(
                        timestamp=now,
                        category=AttackCategory.PORT_SCAN,
                        severity=AlertSeverity.HIGH,
                        title="Vertical Port Scan Detected",
                        description=(
                            f"Host {src_ip} probed {len(distinct_ports)} distinct ports on {dst_ip} "
                            f"within {window:.1f}s window."
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol="TCP",
                        raw_evidence=f"Probed ports: {sorted(list(distinct_ports))[:20]}...",
                        metadata={
                            "distinct_port_count": len(distinct_ports),
                            "window_sec": window,
                        },
                    )
                )

        # 3. Track Horizontal Network Sweep (single port, multiple hosts)
        sweep_key = (src_ip, dst_port)
        self._sweep_history[sweep_key].append((now, dst_ip))
        self._sweep_history[sweep_key] = [
            (ts, ip) for (ts, ip) in self._sweep_history[sweep_key] if now - ts <= window
        ]

        distinct_hosts = {ip for (_, ip) in self._sweep_history[sweep_key]}
        if len(distinct_hosts) >= self.config.sweep_threshold_hosts:
            cooldown_key = (src_ip, f"SWEEP_{dst_port}")
            if now - self._alert_cooldown.get(cooldown_key, 0) > window:
                self._alert_cooldown[cooldown_key] = now
                events.append(
                    SecurityEvent(
                        timestamp=now,
                        category=AttackCategory.PORT_SCAN,
                        severity=AlertSeverity.HIGH,
                        title="Horizontal Network Sweep Detected",
                        description=(
                            f"Host {src_ip} probed port {dst_port} across {len(distinct_hosts)} target hosts "
                            f"within {window:.1f}s window."
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol="TCP",
                        raw_evidence=f"Probed targets: {sorted(list(distinct_hosts))[:10]}...",
                        metadata={
                            "target_host_count": len(distinct_hosts),
                            "target_port": dst_port,
                        },
                    )
                )

        return events

    def _check_stealth_flags(self, packet: DecodedPacket) -> SecurityEvent | None:
        tcp = packet.tcp
        if not tcp or not packet.src_ip:
            return None

        # NULL Scan: All flags 0
        if tcp.flags_raw == 0:
            return SecurityEvent(
                timestamp=packet.timestamp,
                category=AttackCategory.PORT_SCAN,
                severity=AlertSeverity.MEDIUM,
                title="Stealth TCP NULL Scan Detected",
                description=f"Host {packet.src_ip} sent TCP packet with zero flags set to port {packet.dst_port}.",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol="TCP",
                raw_evidence="Flags: 0x00 (NULL)",
            )

        # XMAS Scan: FIN + PSH + URG
        if tcp.flag_fin and tcp.flag_psh and tcp.flag_urg and not tcp.flag_ack and not tcp.flag_syn:
            return SecurityEvent(
                timestamp=packet.timestamp,
                category=AttackCategory.PORT_SCAN,
                severity=AlertSeverity.HIGH,
                title="Stealth TCP XMAS Scan Detected",
                description=f"Host {packet.src_ip} sent TCP XMAS packet (FIN|PSH|URG) to port {packet.dst_port}.",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol="TCP",
                raw_evidence="Flags: FIN|PSH|URG",
            )

        # FIN Scan: Only FIN set
        if tcp.flag_fin and not tcp.flag_syn and not tcp.flag_ack and not tcp.flag_rst and not tcp.flag_psh:
            return SecurityEvent(
                timestamp=packet.timestamp,
                category=AttackCategory.PORT_SCAN,
                severity=AlertSeverity.MEDIUM,
                title="Stealth TCP FIN Scan Detected",
                description=f"Host {packet.src_ip} sent naked TCP FIN packet without active session to port {packet.dst_port}.",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol="TCP",
                raw_evidence="Flags: FIN",
            )

        return None
