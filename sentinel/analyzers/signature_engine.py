"""Signature-based payload inspection and pattern matching engine."""

import re
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional, Pattern
from sentinel.core.models import (
    DecodedPacket,
    SecurityEvent,
    AttackCategory,
    AlertSeverity,
)


@dataclass
class SignatureRule:
    rule_id: str
    category: AttackCategory
    severity: AlertSeverity
    title: str
    description: str
    pattern: Pattern[str]
    target: str  # "URI", "BODY", "HEADER", "RAW", "DNS"


class SignatureEngine:
    """Zero-dependency regex and deterministic signature inspection engine."""

    def __init__(self) -> None:
        self.rules: List[SignatureRule] = []
        self._load_default_signatures()

    def _load_default_signatures(self) -> None:
        # SQL Injection Patterns
        self.register_rule(
            SignatureRule(
                rule_id="SIG-SQLI-001",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.HIGH,
                title="SQL Injection - Classic OR/AND Boolean Tautology",
                description="Detected SQL tautology injection pattern in payload.",
                pattern=re.compile(r"(\b(or|and)\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+|\'\s*or\s*\'1\'\s*=\s*\'1)", re.IGNORECASE),
                target="ALL",
            )
        )
        self.register_rule(
            SignatureRule(
                rule_id="SIG-SQLI-002",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                title="SQL Injection - UNION SELECT Extraction",
                description="Detected UNION-based SQL extraction attempt.",
                pattern=re.compile(r"\bunion\b\s+(all\s+)?\bselect\b", re.IGNORECASE),
                target="ALL",
            )
        )
        self.register_rule(
            SignatureRule(
                rule_id="SIG-SQLI-003",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.HIGH,
                title="SQL Injection - Time-Based Blind / System Catalog",
                description="Detected time-delay or schema discovery SQL functions.",
                pattern=re.compile(r"(\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|\bwaitfor\s+delay\b|\binformation_schema\b)", re.IGNORECASE),
                target="ALL",
            )
        )

        # Directory Traversal Patterns
        self.register_rule(
            SignatureRule(
                rule_id="SIG-TRAV-001",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                title="Directory Traversal - Path Escape Sequence",
                description="Detected path traversal dot-dot-slash sequence or URL encoded equivalent.",
                pattern=re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.IGNORECASE),
                target="ALL",
            )
        )
        self.register_rule(
            SignatureRule(
                rule_id="SIG-TRAV-002",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.CRITICAL,
                title="Directory Traversal - Sensitive System File Probe",
                description="Detected direct access attempt for system credential or config files.",
                pattern=re.compile(r"(/etc/(passwd|shadow|hosts)|c:\\windows\\system32|win\.ini|boot\.ini)", re.IGNORECASE),
                target="ALL",
            )
        )

        # Command Injection Patterns
        self.register_rule(
            SignatureRule(
                rule_id="SIG-CMDI-001",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                title="Command Injection - Shell Execution & Piped Commands",
                description="Detected shell command chaining or binary invocation payload.",
                pattern=re.compile(r"(;\s*(id|whoami|cat\s+/|uname\s+-a|powershell|cmd\.exe|/bin/sh|/bin/bash)|\b(curl|wget)\b\s+https?://)", re.IGNORECASE),
                target="ALL",
            )
        )

        # Cross-Site Scripting (XSS) Patterns
        self.register_rule(
            SignatureRule(
                rule_id="SIG-XSS-001",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                title="Cross-Site Scripting - Script Tag / Event Handler",
                description="Detected reflected or stored script execution vector.",
                pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*|onerror\s*=|onload\s*=|alert\s*\()", re.IGNORECASE),
                target="ALL",
            )
        )

        # Malicious Tool User Agents
        self.register_rule(
            SignatureRule(
                rule_id="SIG-UA-001",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                title="Reconnaissance Tool User-Agent Detected",
                description="Detected scanner/exploit framework User-Agent string.",
                pattern=re.compile(r"\b(sqlmap|nikto|masscan|nmap\s+scripting|dirbuster|gobuster|hydra|wpscan|metasploit)\b", re.IGNORECASE),
                target="HEADER",
            )
        )

        # Web Shell Patterns
        self.register_rule(
            SignatureRule(
                rule_id="SIG-WSHELL-001",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                title="Webshell / Dynamic Code Evaluation",
                description="Detected webshell invocation payload.",
                pattern=re.compile(r"(eval\s*\(\s*base64_decode|passthru\s*\(|system\s*\(\s*\$_(GET|POST|REQUEST)|shell_exec\s*\()", re.IGNORECASE),
                target="ALL",
            )
        )

    def register_rule(self, rule: SignatureRule) -> None:
        self.rules.append(rule)

    def inspect_packet(self, packet: DecodedPacket) -> List[SecurityEvent]:
        """Inspect all available layers of a decoded packet against registered signatures."""
        events: List[SecurityEvent] = []

        inspect_targets: List[tuple[str, str]] = []  # (TargetType, TextContent)

        # HTTP layer inspection
        if packet.http:
            if packet.http.uri:
                inspect_targets.append(("URI", packet.http.uri))
            if packet.http.headers:
                ua = packet.http.headers.get("user-agent", "")
                if ua:
                    inspect_targets.append(("HEADER", f"User-Agent: {ua}"))
                headers_text = " ".join(f"{k}: {v}" for k, v in packet.http.headers.items())
                inspect_targets.append(("HEADER", headers_text))
            if packet.http.body:
                body_text = packet.http.body.decode("latin-1", errors="replace")
                inspect_targets.append(("BODY", body_text))

        # DNS layer inspection
        if packet.dns:
            for q in packet.dns.questions:
                inspect_targets.append(("DNS", q.name))

        # Raw payload inspection
        if packet.payload:
            raw_text = packet.payload.decode("latin-1", errors="replace")
            inspect_targets.append(("RAW", raw_text))

        # Perform match evaluation
        for target_type, content in inspect_targets:
            if not content:
                continue

            # Evaluate both raw and URL-decoded content
            decoded_content = urllib.parse.unquote_plus(content)
            contents_to_test = {content, decoded_content}

            for test_str in contents_to_test:
                matched_rule_ids = set()
                for rule in self.rules:
                    if rule.rule_id in matched_rule_ids:
                        continue
                    if rule.target != "ALL" and rule.target != target_type:
                        continue

                    match = rule.pattern.search(test_str)
                    if match:
                        matched_rule_ids.add(rule.rule_id)
                        matched_snippet = match.group(0)[:120]
                        event = SecurityEvent(
                            timestamp=packet.timestamp,
                            category=rule.category,
                            severity=rule.severity,
                            title=rule.title,
                            description=f"{rule.description} [Matched: {matched_snippet}]",
                            src_ip=packet.src_ip,
                            dst_ip=packet.dst_ip,
                            src_port=packet.src_port,
                            dst_port=packet.dst_port,
                            protocol=packet.protocol_name,
                            raw_evidence=test_str[:250],
                            metadata={"rule_id": rule.rule_id, "matched_pattern": matched_snippet},
                        )
                        events.append(event)

        return events
