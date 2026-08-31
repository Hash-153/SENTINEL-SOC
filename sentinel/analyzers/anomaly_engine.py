"""Statistical anomaly detection, Shannon entropy analyzer, and DNS tunneling detector."""

import math
from collections import Counter, defaultdict
from typing import Dict, List, Tuple
from sentinel.core.models import (
    DecodedPacket,
    SecurityEvent,
    AttackCategory,
    AlertSeverity,
)
from sentinel.core.config import DetectionConfig


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


class AnomalyEngine:
    """Detects statistical traffic bursts, payload entropy anomalies, and DNS tunneling."""

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        # Traffic rate buckets: 1-second buckets -> list of packet counts per second
        self._second_buckets: Dict[int, int] = defaultdict(int)
        self._bucket_history: List[int] = []
        # DNS query tracking per domain
        self._dns_lengths: Dict[str, List[int]] = defaultdict(list)
        # Alert cooldowns
        self._alert_cooldown: Dict[str, float] = {}

    def inspect_packet(self, packet: DecodedPacket) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        now = packet.timestamp

        # 1. Payload Shannon Entropy Check (Non-TLS High Entropy Payload Detection)
        entropy_event = self._check_payload_entropy(packet)
        if entropy_event:
            events.append(entropy_event)

        # 2. DNS Tunneling & DGA Subdomain Anomaly
        dns_event = self._check_dns_anomaly(packet)
        if dns_event:
            events.append(dns_event)

        # 3. Statistical Traffic Volume Burst (Z-score)
        burst_event = self._check_traffic_burst(packet)
        if burst_event:
            events.append(burst_event)

        return events

    def _check_payload_entropy(self, packet: DecodedPacket) -> SecurityEvent | None:
        payload = packet.payload
        if len(payload) < self.config.entropy_min_payload_len:
            return None

        # Exclude standard TLS/HTTPS encrypted transport ports
        if packet.src_port == 443 or packet.dst_port == 443:
            return None

        entropy = calculate_shannon_entropy(payload)
        if entropy >= self.config.entropy_high_threshold:
            cooldown_key = f"ENTROPY_{packet.src_ip}_{packet.dst_port}"
            now = packet.timestamp
            if now - self._alert_cooldown.get(cooldown_key, 0) > 10.0:
                self._alert_cooldown[cooldown_key] = now
                return SecurityEvent(
                    timestamp=now,
                    category=AttackCategory.PAYLOAD_ENTROPY,
                    severity=AlertSeverity.MEDIUM,
                    title="High Shannon Entropy Payload Detected",
                    description=(
                        f"Unusually high byte entropy ({entropy:.2f} / 8.0) detected on port {packet.dst_port}. "
                        "Indicates encrypted shellcode, packed malware, or covert data exfiltration."
                    ),
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol_name,
                    raw_evidence=f"Payload size: {len(payload)} bytes, Entropy: {entropy:.3f} bits/byte",
                    metadata={"entropy": entropy, "payload_len": len(payload)},
                )
        return None

    def _check_dns_anomaly(self, packet: DecodedPacket) -> SecurityEvent | None:
        if not packet.dns or not packet.dns.questions:
            return None

        for q in packet.dns.questions:
            qname = q.name.lower()
            labels = qname.split(".")
            subdomain = labels[0] if labels else ""

            # Check for unusually long queries or high entropy subdomains
            if len(subdomain) > 25 or len(qname) > 50:
                sub_entropy = calculate_shannon_entropy(subdomain.encode("ascii", errors="replace"))
                if sub_entropy >= 3.4 or len(subdomain) >= 40:
                    cooldown_key = f"DNS_TUNNEL_{packet.src_ip}_{qname}"
                    now = packet.timestamp
                    if now - self._alert_cooldown.get(cooldown_key, 0) > 15.0:
                        self._alert_cooldown[cooldown_key] = now
                        return SecurityEvent(
                            timestamp=now,
                            category=AttackCategory.DNS_ANOMALY,
                            severity=AlertSeverity.HIGH,
                            title="DNS Tunneling / Data Exfiltration Anomaly",
                            description=(
                                f"Anomalous high-entropy DNS query detected: '{qname[:50]}...' "
                                f"(Length: {len(qname)}, Subdomain Entropy: {sub_entropy:.2f})."
                            ),
                            src_ip=packet.src_ip,
                            dst_ip=packet.dst_ip,
                            src_port=packet.src_port,
                            dst_port=packet.dst_port or 53,
                            protocol="DNS",
                            raw_evidence=f"Query: {qname}, Subdomain: {subdomain}",
                            metadata={"query_name": qname, "entropy": sub_entropy},
                        )
        return None

    def _check_traffic_burst(self, packet: DecodedPacket) -> SecurityEvent | None:
        now = packet.timestamp
        current_second = int(now)

        self._second_buckets[current_second] += 1

        # Keep history of completed seconds
        old_seconds = [s for s in self._second_buckets.keys() if current_second - s > 60]
        for s in old_seconds:
            self._bucket_history.append(self._second_buckets.pop(s))

        # Maintain last 60 seconds history
        if len(self._bucket_history) > 120:
            self._bucket_history = self._bucket_history[-60:]

        if len(self._bucket_history) >= self.config.min_packets_for_baseline:
            mean = sum(self._bucket_history) / len(self._bucket_history)
            variance = sum((x - mean) ** 2 for x in self._bucket_history) / len(self._bucket_history)
            std_dev = math.sqrt(variance)

            if std_dev > 1.0:
                current_rate = self._second_buckets[current_second]
                z_score = (current_rate - mean) / std_dev

                if z_score >= self.config.z_score_threshold:
                    cooldown_key = f"BURST_{packet.src_ip}"
                    if now - self._alert_cooldown.get(cooldown_key, 0) > 20.0:
                        self._alert_cooldown[cooldown_key] = now
                        return SecurityEvent(
                            timestamp=now,
                            category=AttackCategory.TRAFFIC_BURST,
                            severity=AlertSeverity.HIGH,
                            title="Statistical Traffic Volume Spike / Volumetric Anomaly",
                            description=(
                                f"Packet rate of {current_rate} pkts/sec is {z_score:.2f} standard deviations "
                                f"above baseline mean ({mean:.1f} pkts/sec)."
                            ),
                            src_ip=packet.src_ip,
                            dst_ip=packet.dst_ip,
                            protocol=packet.protocol_name,
                            raw_evidence=f"Rate: {current_rate}/s, Baseline Mean: {mean:.1f}, Z-Score: {z_score:.2f}",
                            metadata={"rate": current_rate, "mean": mean, "z_score": z_score},
                        )
        return None
