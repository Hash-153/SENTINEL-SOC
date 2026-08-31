"""Core domain models and strongly-typed data structures for Sentinel."""

from __future__ import annotations
import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


class IpProtocol(enum.IntEnum):
    ICMP = 1
    TCP = 6
    UDP = 17
    UNKNOWN = 255

    @classmethod
    def from_int(cls, value: int) -> IpProtocol:
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN


class AlertSeverity(enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def score(self) -> int:
        mapping = {
            "INFO": 10,
            "LOW": 25,
            "MEDIUM": 50,
            "HIGH": 75,
            "CRITICAL": 100,
        }
        return mapping.get(self.value, 0)


class AttackCategory(enum.Enum):
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    XSS_ATTACK = "XSS_ATTACK"
    DNS_ANOMALY = "DNS_ANOMALY"
    TRAFFIC_BURST = "TRAFFIC_BURST"
    PAYLOAD_ENTROPY = "PAYLOAD_ENTROPY"
    MALICIOUS_PAYLOAD = "MALICIOUS_PAYLOAD"
    SUSPICIOUS_HEADER = "SUSPICIOUS_HEADER"


@dataclass
class EthernetFrame:
    src_mac: str
    dst_mac: str
    eth_type: int
    payload: bytes


@dataclass
class IPv4Header:
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: IpProtocol
    checksum: int
    src_ip: str
    dst_ip: str
    payload: bytes


@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    data_offset: int
    flags_raw: int
    flag_fin: bool
    flag_syn: bool
    flag_rst: bool
    flag_psh: bool
    flag_ack: bool
    flag_urg: bool
    flag_ece: bool
    flag_cwr: bool
    window_size: int
    checksum: int
    urgent_pointer: int
    payload: bytes

    @property
    def flags_summary(self) -> str:
        flags = []
        if self.flag_syn:
            flags.append("SYN")
        if self.flag_ack:
            flags.append("ACK")
        if self.flag_fin:
            flags.append("FIN")
        if self.flag_rst:
            flags.append("RST")
        if self.flag_psh:
            flags.append("PSH")
        if self.flag_urg:
            flags.append("URG")
        return "|".join(flags) if flags else "NONE"


@dataclass
class UDPHeader:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes


@dataclass
class DNSQuestion:
    name: str
    qtype: int
    qclass: int


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: str


@dataclass
class DNSMessage:
    tx_id: int
    is_response: bool
    opcode: int
    authoritative: bool
    truncated: bool
    recursion_desired: bool
    recursion_available: bool
    response_code: int
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSRecord] = field(default_factory=list)


@dataclass
class HTTPTransaction:
    is_request: bool
    method: Optional[str] = None
    uri: Optional[str] = None
    version: Optional[str] = None
    status_code: Optional[int] = None
    reason_phrase: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""


@dataclass
class DecodedPacket:
    timestamp: float
    raw_length: int
    raw_data: bytes
    eth: Optional[EthernetFrame] = None
    ip: Optional[IPv4Header] = None
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None
    dns: Optional[DNSMessage] = None
    http: Optional[HTTPTransaction] = None

    @property
    def src_ip(self) -> Optional[str]:
        return self.ip.src_ip if self.ip else None

    @property
    def dst_ip(self) -> Optional[str]:
        return self.ip.dst_ip if self.ip else None

    @property
    def src_port(self) -> Optional[int]:
        if self.tcp:
            return self.tcp.src_port
        if self.udp:
            return self.udp.src_port
        return None

    @property
    def dst_port(self) -> Optional[int]:
        if self.tcp:
            return self.tcp.dst_port
        if self.udp:
            return self.udp.dst_port
        return None

    @property
    def protocol_name(self) -> str:
        if self.tcp:
            return "TCP"
        if self.udp:
            return "UDP"
        if self.ip:
            return self.ip.protocol.name
        return "UNKNOWN"

    @property
    def payload(self) -> bytes:
        if self.tcp:
            return self.tcp.payload
        if self.udp:
            return self.udp.payload
        if self.ip:
            return self.ip.payload
        return self.raw_data


@dataclass
class SecurityEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    category: AttackCategory = AttackCategory.MALICIOUS_PAYLOAD
    severity: AlertSeverity = AlertSeverity.LOW
    title: str = ""
    description: str = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "IP"
    raw_evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "raw_evidence": self.raw_evidence,
            "metadata": self.metadata,
        }


@dataclass
class Incident:
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    title: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    src_ip: Optional[str] = None
    target_ips: List[str] = field(default_factory=list)
    event_count: int = 0
    events: List[SecurityEvent] = field(default_factory=list)
    status: str = "OPEN"
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "title": self.title,
            "severity": self.severity.value,
            "src_ip": self.src_ip,
            "target_ips": self.target_ips,
            "event_count": self.event_count,
            "events": [e.to_dict() for e in self.events],
            "status": self.status,
            "summary": self.summary,
        }
