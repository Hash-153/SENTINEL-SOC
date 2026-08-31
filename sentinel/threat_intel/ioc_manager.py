"""Indicators of Compromise (IoC) Management and Threat Intelligence Matching Engine."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import enum
import time


class IocType(enum.Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    MD5 = "MD5"
    SHA256 = "SHA256"
    USER_AGENT = "USER_AGENT"
    EMAIL = "EMAIL"


@dataclass
class IndicatorOfCompromise:
    value: str
    ioc_type: IocType
    threat_actor: str
    campaign: str
    confidence: int  # 1 to 100
    first_seen: float
    last_seen: float
    description: str
    tags: List[str] = field(default_factory=list)


class IocManager:
    """High-performance in-memory repository for Indicators of Compromise."""

    def __init__(self) -> None:
        self.indicators: Dict[str, IndicatorOfCompromise] = {}
        self.ip_index: Set[str] = set()
        self.domain_index: Set[str] = set()
        self.hash_index: Set[str] = set()
        self._load_threat_feed()

    def add_ioc(self, ioc: IndicatorOfCompromise) -> None:
        self.indicators[ioc.value.lower()] = ioc
        if ioc.ioc_type in (IocType.IPV4, IocType.IPV6):
            self.ip_index.add(ioc.value)
        elif ioc.ioc_type == IocType.DOMAIN:
            self.domain_index.add(ioc.value.lower())
        elif ioc.ioc_type in (IocType.MD5, IocType.SHA256):
            self.hash_index.add(ioc.value.lower())

    def match_ip(self, ip_address: str) -> Optional[IndicatorOfCompromise]:
        return self.indicators.get(ip_address)

    def match_domain(self, domain: str) -> Optional[IndicatorOfCompromise]:
        return self.indicators.get(domain.lower())

    def _load_threat_feed(self) -> None:
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.1",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #1",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #1.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-1.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #1",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #1.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.2",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #2",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #2.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-2.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #2",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #2.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.3",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #3",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #3.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-3.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #3",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #3.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.4",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #4",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #4.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-4.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #4",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #4.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.5",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #5",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #5.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-5.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #5",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #5.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.6",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #6",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #6.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-6.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #6",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #6.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.7",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #7",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #7.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-7.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #7",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #7.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.8",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #8",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #8.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-8.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #8",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #8.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.9",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #9",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #9.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-9.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #9",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #9.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.10",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #10",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #10.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-10.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #10",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #10.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.11",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #11",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #11.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-11.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #11",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #11.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.12",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #12",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #12.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-12.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #12",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #12.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.13",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #13",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #13.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-13.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #13",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #13.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.14",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #14",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #14.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-14.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #14",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #14.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.15",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #15",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #15.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-15.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #15",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #15.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.16",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #16",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #16.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-16.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #16",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #16.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.17",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #17",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #17.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-17.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #17",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #17.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.18",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #18",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #18.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-18.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #18",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #18.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.19",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #19",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #19.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-19.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #19",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #19.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.20",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #20",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #20.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-20.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #20",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #20.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.21",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #21",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #21.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-21.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #21",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #21.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.22",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #22",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #22.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-22.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #22",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #22.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.23",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #23",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #23.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-23.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #23",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #23.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.24",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #24",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #24.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-24.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #24",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #24.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.25",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #25",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #25.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-25.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #25",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #25.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.26",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #26",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #26.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-26.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #26",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #26.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.27",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #27",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #27.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-27.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #27",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #27.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.28",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #28",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #28.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-28.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #28",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #28.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.29",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #29",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #29.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-29.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #29",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #29.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.30",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #30",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #30.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-30.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #30",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #30.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.31",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #31",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #31.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-31.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #31",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #31.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.32",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #32",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #32.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-32.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #32",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #32.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.33",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #33",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #33.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-33.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #33",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #33.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.34",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #34",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #34.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-34.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #34",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #34.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.35",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #35",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #35.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-35.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #35",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #35.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.36",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #36",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #36.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-36.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #36",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #36.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.37",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #37",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #37.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-37.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #37",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #37.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.38",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #38",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #38.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-38.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #38",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #38.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.39",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #39",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #39.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-39.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #39",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #39.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.40",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #40",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #40.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-40.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #40",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #40.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.41",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #41",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #41.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-41.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #41",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #41.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.42",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #42",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #42.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-42.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #42",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #42.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.43",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #43",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #43.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-43.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #43",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #43.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.44",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #44",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #44.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-44.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #44",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #44.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.45",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #45",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #45.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-45.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #45",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #45.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.46",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #46",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #46.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-46.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #46",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #46.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.47",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #47",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #47.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-47.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #47",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #47.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.48",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #48",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #48.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-48.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #48",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #48.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.49",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #49",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #49.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-49.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #49",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #49.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.50",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #50",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #50.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-50.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #50",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #50.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.51",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #51",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #51.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-51.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #51",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #51.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.52",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #52",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #52.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-52.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #52",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #52.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.53",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #53",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #53.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-53.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #53",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #53.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.54",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #54",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #54.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-54.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #54",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #54.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.55",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #55",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #55.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-55.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #55",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #55.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.56",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #56",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #56.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-56.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #56",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #56.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.57",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #57",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #57.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-57.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #57",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #57.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.58",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #58",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #58.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-58.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #58",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #58.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.59",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #59",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #59.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-59.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #59",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #59.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.60",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #60",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #60.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-60.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #60",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #60.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.61",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #61",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #61.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-61.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #61",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #61.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.62",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #62",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #62.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-62.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #62",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #62.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.63",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #63",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #63.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-63.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #63",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #63.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.64",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #64",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #64.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-64.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #64",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #64.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.65",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #65",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #65.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-65.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #65",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #65.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.66",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #66",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #66.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-66.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #66",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #66.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.67",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #67",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #67.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-67.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #67",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #67.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.68",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #68",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #68.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-68.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #68",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #68.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.69",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #69",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #69.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-69.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #69",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #69.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.70",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #70",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #70.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-70.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #70",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #70.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.71",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #71",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #71.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-71.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #71",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #71.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.72",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #72",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #72.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-72.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #72",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #72.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.73",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #73",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #73.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-73.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #73",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #73.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.74",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #74",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #74.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-74.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #74",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #74.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.75",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #75",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #75.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-75.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #75",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #75.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.76",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #76",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #76.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-76.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #76",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #76.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.77",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #77",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #77.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-77.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #77",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #77.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.78",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #78",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #78.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-78.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #78",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #78.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.79",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #79",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #79.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-79.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #79",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #79.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.80",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #80",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #80.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-80.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #80",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #80.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.81",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #81",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #81.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-81.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #81",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #81.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.82",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #82",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #82.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-82.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #82",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #82.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.83",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #83",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #83.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-83.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #83",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #83.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.84",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #84",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #84.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-84.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #84",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #84.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.85",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #85",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #85.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-85.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #85",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #85.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.86",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #86",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #86.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-86.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #86",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #86.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.87",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #87",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #87.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-87.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #87",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #87.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.88",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #88",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #88.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-88.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #88",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #88.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.89",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #89",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #89.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-89.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #89",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #89.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.90",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #90",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #90.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-90.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #90",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #90.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.91",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #91",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #91.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-91.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #91",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #91.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.92",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #92",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #92.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-92.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #92",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #92.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.93",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #93",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #93.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-93.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #93",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #93.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.94",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #94",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #94.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-94.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #94",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #94.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.95",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #95",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #95.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-95.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #95",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #95.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.96",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #96",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #96.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-96.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #96",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #96.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.97",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #97",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #97.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-97.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #97",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #97.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.98",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #98",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #98.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-98.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #98",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #98.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.99",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #99",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #99.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-99.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #99",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #99.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.100",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #100",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #100.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-100.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #100",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #100.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.101",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #101",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #101.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-101.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #101",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #101.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.102",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #102",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #102.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-102.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #102",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #102.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.103",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #103",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #103.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-103.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #103",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #103.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.104",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #104",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #104.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-104.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #104",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #104.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.105",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #105",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #105.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-105.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #105",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #105.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.106",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #106",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #106.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-106.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #106",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #106.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.107",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #107",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #107.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-107.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #107",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #107.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.108",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #108",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #108.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-108.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #108",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #108.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.109",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #109",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #109.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-109.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #109",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #109.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.110",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #110",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #110.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-110.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #110",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #110.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.111",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #111",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #111.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-111.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #111",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #111.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.112",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #112",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #112.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-112.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #112",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #112.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.113",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #113",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #113.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-113.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #113",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #113.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.114",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #114",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #114.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-114.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #114",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #114.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.115",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #115",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #115.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-115.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #115",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #115.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.116",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #116",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #116.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-116.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #116",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #116.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.117",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #117",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #117.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-117.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #117",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #117.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.118",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #118",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #118.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-118.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #118",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #118.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.119",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #119",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #119.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-119.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #119",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #119.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.120",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #120",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #120.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-120.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #120",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #120.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.121",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #121",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #121.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-121.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #121",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #121.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.122",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #122",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #122.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-122.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #122",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #122.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.123",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #123",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #123.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-123.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #123",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #123.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.124",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #124",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #124.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-124.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #124",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #124.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.125",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #125",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #125.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-125.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #125",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #125.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.126",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #126",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #126.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-126.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #126",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #126.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.127",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #127",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #127.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-127.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #127",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #127.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.128",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #128",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #128.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-128.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #128",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #128.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.129",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #129",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #129.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-129.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #129",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #129.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.130",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #130",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #130.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-130.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #130",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #130.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.131",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #131",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #131.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-131.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #131",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #131.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.132",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #132",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #132.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-132.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #132",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #132.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.133",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #133",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #133.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-133.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #133",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #133.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.134",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #134",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #134.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-134.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #134",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #134.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.135",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #135",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #135.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-135.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #135",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #135.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.136",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #136",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #136.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-136.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #136",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #136.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.137",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #137",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #137.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-137.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #137",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #137.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.138",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #138",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #138.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-138.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #138",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #138.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.139",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #139",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #139.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-139.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #139",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #139.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.140",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #140",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #140.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-140.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #140",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #140.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.141",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #141",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #141.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-141.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #141",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #141.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.142",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #142",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #142.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-142.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #142",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #142.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.143",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #143",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #143.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-143.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #143",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #143.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.144",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #144",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #144.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-144.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #144",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #144.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.145",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #145",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #145.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-145.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #145",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #145.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.146",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #146",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #146.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-146.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #146",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #146.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.147",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #147",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #147.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-147.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #147",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #147.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.148",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #148",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #148.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-148.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #148",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #148.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.149",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #149",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #149.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-149.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #149",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #149.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.150",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #150",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #150.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-150.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #150",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #150.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.151",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #151",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #151.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-151.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #151",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #151.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.152",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #152",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #152.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-152.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #152",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #152.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.153",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #153",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #153.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-153.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #153",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #153.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.154",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #154",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #154.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-154.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #154",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #154.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.155",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #155",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #155.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-155.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #155",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #155.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.156",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #156",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #156.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-156.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #156",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #156.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.157",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #157",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #157.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-157.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #157",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #157.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.158",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #158",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #158.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-158.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #158",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #158.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="198.51.100.159",
                ioc_type=IocType.IPV4,
                threat_actor="APT-29 (CozyBear)",
                campaign="Operation StealthDagger #159",
                confidence=95,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Known command and control drop point and exfiltration relay #159.",
                tags=["c2", "apt", "exfiltration", "malware-delivery", "botnet-controller"],
            )
        )
        self.add_ioc(
            IndicatorOfCompromise(
                value="c2-node-159.darknet-relay.cc",
                ioc_type=IocType.DOMAIN,
                threat_actor="Lazarus Group",
                campaign="Campaign CryptoDrain #159",
                confidence=92,
                first_seen=1700000000.0,
                last_seen=time.time(),
                description="Fast-flux dynamic DNS beaconing endpoint for payload delivery #159.",
                tags=["fast-flux", "dga", "c2", "ransomware", "trojan-distribution"],
            )
        )
