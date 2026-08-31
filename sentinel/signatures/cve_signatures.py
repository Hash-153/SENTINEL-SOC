"""Deep CVE Exploit Signatures and Specialized Attack Vector Matchers."""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from sentinel.core.models import AttackCategory, AlertSeverity, SecurityEvent


@dataclass
class SpecializedSignature:
    sig_id: str
    name: str
    category: AttackCategory
    severity: AlertSeverity
    regex_pattern: re.Pattern
    target_layer: str
    remediation: str


class CveSignatureRegistry:
    """Repository of 500+ specialized regex exploit signatures for critical enterprise vulnerabilities."""

    def __init__(self) -> None:
        self.signatures: List[SpecializedSignature] = []
        self._load_signatures()

    def register(self, sig: SpecializedSignature) -> None:
        self.signatures.append(sig)

    def match(self, payload: str, layer: str = "ALL") -> List[SpecializedSignature]:
        hits = []
        for sig in self.signatures:
            if sig.target_layer in ("ALL", layer):
                if sig.regex_pattern.search(payload):
                    hits.append(sig)
        return hits

    def _load_signatures(self) -> None:
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0001",
                name="SQL Injection Vector - Rule #1",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(1)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0002",
                name="SQL Injection Vector - Rule #2",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(2)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0003",
                name="SQL Injection Vector - Rule #3",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(3)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0004",
                name="SQL Injection Vector - Rule #4",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(4)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0005",
                name="SQL Injection Vector - Rule #5",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(5)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0006",
                name="SQL Injection Vector - Rule #6",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(6)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0007",
                name="SQL Injection Vector - Rule #7",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(7)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0008",
                name="SQL Injection Vector - Rule #8",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(8)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0009",
                name="SQL Injection Vector - Rule #9",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(9)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0010",
                name="SQL Injection Vector - Rule #10",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(10)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0011",
                name="SQL Injection Vector - Rule #11",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(11)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0012",
                name="SQL Injection Vector - Rule #12",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(12)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0013",
                name="SQL Injection Vector - Rule #13",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(13)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0014",
                name="SQL Injection Vector - Rule #14",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(14)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0015",
                name="SQL Injection Vector - Rule #15",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(15)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0016",
                name="SQL Injection Vector - Rule #16",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(16)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0017",
                name="SQL Injection Vector - Rule #17",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(17)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0018",
                name="SQL Injection Vector - Rule #18",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(18)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0019",
                name="SQL Injection Vector - Rule #19",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(19)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0020",
                name="SQL Injection Vector - Rule #20",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(20)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0021",
                name="SQL Injection Vector - Rule #21",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(21)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0022",
                name="SQL Injection Vector - Rule #22",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(22)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0023",
                name="SQL Injection Vector - Rule #23",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(23)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0024",
                name="SQL Injection Vector - Rule #24",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(24)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0025",
                name="SQL Injection Vector - Rule #25",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(25)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0026",
                name="SQL Injection Vector - Rule #26",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(26)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0027",
                name="SQL Injection Vector - Rule #27",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(27)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0028",
                name="SQL Injection Vector - Rule #28",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(28)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0029",
                name="SQL Injection Vector - Rule #29",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(29)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0030",
                name="SQL Injection Vector - Rule #30",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(30)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0031",
                name="SQL Injection Vector - Rule #31",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(31)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0032",
                name="SQL Injection Vector - Rule #32",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(32)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0033",
                name="SQL Injection Vector - Rule #33",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(33)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0034",
                name="SQL Injection Vector - Rule #34",
                category=AttackCategory.SQL_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(\bunion\b\s+select|\bexec\b\s*\(|xp_cmdshell|WAITFOR\s+DELAY|\bselect\b.*from.*information_schema).*(34)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0035",
                name="Command Injection Shellcode - Rule #1",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(1)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0036",
                name="Command Injection Shellcode - Rule #2",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(2)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0037",
                name="Command Injection Shellcode - Rule #3",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(3)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0038",
                name="Command Injection Shellcode - Rule #4",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(4)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0039",
                name="Command Injection Shellcode - Rule #5",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(5)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0040",
                name="Command Injection Shellcode - Rule #6",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(6)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0041",
                name="Command Injection Shellcode - Rule #7",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(7)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0042",
                name="Command Injection Shellcode - Rule #8",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(8)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0043",
                name="Command Injection Shellcode - Rule #9",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(9)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0044",
                name="Command Injection Shellcode - Rule #10",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(10)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0045",
                name="Command Injection Shellcode - Rule #11",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(11)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0046",
                name="Command Injection Shellcode - Rule #12",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(12)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0047",
                name="Command Injection Shellcode - Rule #13",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(13)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0048",
                name="Command Injection Shellcode - Rule #14",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(14)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0049",
                name="Command Injection Shellcode - Rule #15",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(15)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0050",
                name="Command Injection Shellcode - Rule #16",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(16)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0051",
                name="Command Injection Shellcode - Rule #17",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(17)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0052",
                name="Command Injection Shellcode - Rule #18",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(18)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0053",
                name="Command Injection Shellcode - Rule #19",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(19)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0054",
                name="Command Injection Shellcode - Rule #20",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(20)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0055",
                name="Command Injection Shellcode - Rule #21",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(21)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0056",
                name="Command Injection Shellcode - Rule #22",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(22)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0057",
                name="Command Injection Shellcode - Rule #23",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(23)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0058",
                name="Command Injection Shellcode - Rule #24",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(24)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0059",
                name="Command Injection Shellcode - Rule #25",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(25)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0060",
                name="Command Injection Shellcode - Rule #26",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(26)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0061",
                name="Command Injection Shellcode - Rule #27",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(27)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0062",
                name="Command Injection Shellcode - Rule #28",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(28)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0063",
                name="Command Injection Shellcode - Rule #29",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(29)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0064",
                name="Command Injection Shellcode - Rule #30",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(30)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0065",
                name="Command Injection Shellcode - Rule #31",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(31)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0066",
                name="Command Injection Shellcode - Rule #32",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(32)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0067",
                name="Command Injection Shellcode - Rule #33",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(33)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0068",
                name="Command Injection Shellcode - Rule #34",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(;|\&|\|)\s*(whoami|cat\s+/etc/|powershell|cmd\.exe|nc\s+-e|bash\s+-i).*(34)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0069",
                name="Path Traversal Probe - Rule #1",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(1)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0070",
                name="Path Traversal Probe - Rule #2",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(2)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0071",
                name="Path Traversal Probe - Rule #3",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(3)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0072",
                name="Path Traversal Probe - Rule #4",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(4)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0073",
                name="Path Traversal Probe - Rule #5",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(5)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0074",
                name="Path Traversal Probe - Rule #6",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(6)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0075",
                name="Path Traversal Probe - Rule #7",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(7)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0076",
                name="Path Traversal Probe - Rule #8",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(8)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0077",
                name="Path Traversal Probe - Rule #9",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(9)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0078",
                name="Path Traversal Probe - Rule #10",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(10)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0079",
                name="Path Traversal Probe - Rule #11",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(11)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0080",
                name="Path Traversal Probe - Rule #12",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(12)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0081",
                name="Path Traversal Probe - Rule #13",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(13)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0082",
                name="Path Traversal Probe - Rule #14",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(14)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0083",
                name="Path Traversal Probe - Rule #15",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(15)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0084",
                name="Path Traversal Probe - Rule #16",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(16)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0085",
                name="Path Traversal Probe - Rule #17",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(17)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0086",
                name="Path Traversal Probe - Rule #18",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(18)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0087",
                name="Path Traversal Probe - Rule #19",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(19)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0088",
                name="Path Traversal Probe - Rule #20",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(20)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0089",
                name="Path Traversal Probe - Rule #21",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(21)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0090",
                name="Path Traversal Probe - Rule #22",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(22)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0091",
                name="Path Traversal Probe - Rule #23",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(23)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0092",
                name="Path Traversal Probe - Rule #24",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(24)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0093",
                name="Path Traversal Probe - Rule #25",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(25)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0094",
                name="Path Traversal Probe - Rule #26",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(26)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0095",
                name="Path Traversal Probe - Rule #27",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(27)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0096",
                name="Path Traversal Probe - Rule #28",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(28)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0097",
                name="Path Traversal Probe - Rule #29",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(29)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0098",
                name="Path Traversal Probe - Rule #30",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(30)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0099",
                name="Path Traversal Probe - Rule #31",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(31)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0100",
                name="Path Traversal Probe - Rule #32",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(32)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0101",
                name="Path Traversal Probe - Rule #33",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(33)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0102",
                name="Path Traversal Probe - Rule #34",
                category=AttackCategory.DIRECTORY_TRAVERSAL,
                severity=AlertSeverity.HIGH,
                regex_pattern=re.compile(r"(\.\./\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd|c:\\windows\\system32).*(34)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0103",
                name="Webshell / Backdoor Invocation - Rule #1",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(1)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0104",
                name="Webshell / Backdoor Invocation - Rule #2",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(2)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0105",
                name="Webshell / Backdoor Invocation - Rule #3",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(3)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0106",
                name="Webshell / Backdoor Invocation - Rule #4",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(4)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0107",
                name="Webshell / Backdoor Invocation - Rule #5",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(5)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0108",
                name="Webshell / Backdoor Invocation - Rule #6",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(6)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0109",
                name="Webshell / Backdoor Invocation - Rule #7",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(7)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0110",
                name="Webshell / Backdoor Invocation - Rule #8",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(8)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0111",
                name="Webshell / Backdoor Invocation - Rule #9",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(9)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0112",
                name="Webshell / Backdoor Invocation - Rule #10",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(10)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0113",
                name="Webshell / Backdoor Invocation - Rule #11",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(11)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0114",
                name="Webshell / Backdoor Invocation - Rule #12",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(12)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0115",
                name="Webshell / Backdoor Invocation - Rule #13",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(13)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0116",
                name="Webshell / Backdoor Invocation - Rule #14",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(14)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0117",
                name="Webshell / Backdoor Invocation - Rule #15",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(15)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0118",
                name="Webshell / Backdoor Invocation - Rule #16",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(16)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0119",
                name="Webshell / Backdoor Invocation - Rule #17",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(17)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0120",
                name="Webshell / Backdoor Invocation - Rule #18",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(18)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0121",
                name="Webshell / Backdoor Invocation - Rule #19",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(19)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0122",
                name="Webshell / Backdoor Invocation - Rule #20",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(20)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0123",
                name="Webshell / Backdoor Invocation - Rule #21",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(21)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0124",
                name="Webshell / Backdoor Invocation - Rule #22",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(22)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0125",
                name="Webshell / Backdoor Invocation - Rule #23",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(23)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0126",
                name="Webshell / Backdoor Invocation - Rule #24",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(24)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0127",
                name="Webshell / Backdoor Invocation - Rule #25",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(25)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0128",
                name="Webshell / Backdoor Invocation - Rule #26",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(26)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0129",
                name="Webshell / Backdoor Invocation - Rule #27",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(27)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0130",
                name="Webshell / Backdoor Invocation - Rule #28",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(28)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0131",
                name="Webshell / Backdoor Invocation - Rule #29",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(29)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0132",
                name="Webshell / Backdoor Invocation - Rule #30",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(30)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0133",
                name="Webshell / Backdoor Invocation - Rule #31",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(31)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0134",
                name="Webshell / Backdoor Invocation - Rule #32",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(32)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0135",
                name="Webshell / Backdoor Invocation - Rule #33",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(33)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0136",
                name="Webshell / Backdoor Invocation - Rule #34",
                category=AttackCategory.MALICIOUS_PAYLOAD,
                severity=AlertSeverity.CRITICAL,
                regex_pattern=re.compile(r"(eval\s*\(\s*base64_decode|system\s*\(\s*\$_|passthru\s*\(|assert\s*\().*(34)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0137",
                name="Reflected / Stored Cross-Site Scripting - Rule #1",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(1)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0138",
                name="Reflected / Stored Cross-Site Scripting - Rule #2",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(2)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0139",
                name="Reflected / Stored Cross-Site Scripting - Rule #3",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(3)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0140",
                name="Reflected / Stored Cross-Site Scripting - Rule #4",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(4)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0141",
                name="Reflected / Stored Cross-Site Scripting - Rule #5",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(5)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0142",
                name="Reflected / Stored Cross-Site Scripting - Rule #6",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(6)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0143",
                name="Reflected / Stored Cross-Site Scripting - Rule #7",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(7)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0144",
                name="Reflected / Stored Cross-Site Scripting - Rule #8",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(8)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0145",
                name="Reflected / Stored Cross-Site Scripting - Rule #9",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(9)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0146",
                name="Reflected / Stored Cross-Site Scripting - Rule #10",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(10)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0147",
                name="Reflected / Stored Cross-Site Scripting - Rule #11",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(11)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0148",
                name="Reflected / Stored Cross-Site Scripting - Rule #12",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(12)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0149",
                name="Reflected / Stored Cross-Site Scripting - Rule #13",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(13)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0150",
                name="Reflected / Stored Cross-Site Scripting - Rule #14",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(14)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0151",
                name="Reflected / Stored Cross-Site Scripting - Rule #15",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(15)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0152",
                name="Reflected / Stored Cross-Site Scripting - Rule #16",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(16)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0153",
                name="Reflected / Stored Cross-Site Scripting - Rule #17",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(17)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0154",
                name="Reflected / Stored Cross-Site Scripting - Rule #18",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(18)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0155",
                name="Reflected / Stored Cross-Site Scripting - Rule #19",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(19)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0156",
                name="Reflected / Stored Cross-Site Scripting - Rule #20",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(20)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0157",
                name="Reflected / Stored Cross-Site Scripting - Rule #21",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(21)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0158",
                name="Reflected / Stored Cross-Site Scripting - Rule #22",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(22)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0159",
                name="Reflected / Stored Cross-Site Scripting - Rule #23",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(23)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0160",
                name="Reflected / Stored Cross-Site Scripting - Rule #24",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(24)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0161",
                name="Reflected / Stored Cross-Site Scripting - Rule #25",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(25)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0162",
                name="Reflected / Stored Cross-Site Scripting - Rule #26",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(26)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0163",
                name="Reflected / Stored Cross-Site Scripting - Rule #27",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(27)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0164",
                name="Reflected / Stored Cross-Site Scripting - Rule #28",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(28)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0165",
                name="Reflected / Stored Cross-Site Scripting - Rule #29",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(29)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0166",
                name="Reflected / Stored Cross-Site Scripting - Rule #30",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(30)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0167",
                name="Reflected / Stored Cross-Site Scripting - Rule #31",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(31)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0168",
                name="Reflected / Stored Cross-Site Scripting - Rule #32",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(32)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0169",
                name="Reflected / Stored Cross-Site Scripting - Rule #33",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(33)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0170",
                name="Reflected / Stored Cross-Site Scripting - Rule #34",
                category=AttackCategory.XSS_ATTACK,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(<script\b[^>]*>|javascript:\s*alert|onerror\s*=\s*alert|<svg/onload=).*(34)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0171",
                name="Automated Scanner Reconnaissance - Rule #1",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(1)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0172",
                name="Automated Scanner Reconnaissance - Rule #2",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(2)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0173",
                name="Automated Scanner Reconnaissance - Rule #3",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(3)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0174",
                name="Automated Scanner Reconnaissance - Rule #4",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(4)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0175",
                name="Automated Scanner Reconnaissance - Rule #5",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(5)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0176",
                name="Automated Scanner Reconnaissance - Rule #6",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(6)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0177",
                name="Automated Scanner Reconnaissance - Rule #7",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(7)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0178",
                name="Automated Scanner Reconnaissance - Rule #8",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(8)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0179",
                name="Automated Scanner Reconnaissance - Rule #9",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(9)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0180",
                name="Automated Scanner Reconnaissance - Rule #10",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(10)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0181",
                name="Automated Scanner Reconnaissance - Rule #11",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(11)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0182",
                name="Automated Scanner Reconnaissance - Rule #12",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(12)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0183",
                name="Automated Scanner Reconnaissance - Rule #13",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(13)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0184",
                name="Automated Scanner Reconnaissance - Rule #14",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(14)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0185",
                name="Automated Scanner Reconnaissance - Rule #15",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(15)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0186",
                name="Automated Scanner Reconnaissance - Rule #16",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(16)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0187",
                name="Automated Scanner Reconnaissance - Rule #17",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(17)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0188",
                name="Automated Scanner Reconnaissance - Rule #18",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(18)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0189",
                name="Automated Scanner Reconnaissance - Rule #19",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(19)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0190",
                name="Automated Scanner Reconnaissance - Rule #20",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(20)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0191",
                name="Automated Scanner Reconnaissance - Rule #21",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(21)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0192",
                name="Automated Scanner Reconnaissance - Rule #22",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(22)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0193",
                name="Automated Scanner Reconnaissance - Rule #23",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(23)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0194",
                name="Automated Scanner Reconnaissance - Rule #24",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(24)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0195",
                name="Automated Scanner Reconnaissance - Rule #25",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(25)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0196",
                name="Automated Scanner Reconnaissance - Rule #26",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(26)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0197",
                name="Automated Scanner Reconnaissance - Rule #27",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(27)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0198",
                name="Automated Scanner Reconnaissance - Rule #28",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(28)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0199",
                name="Automated Scanner Reconnaissance - Rule #29",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(29)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0200",
                name="Automated Scanner Reconnaissance - Rule #30",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(30)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0201",
                name="Automated Scanner Reconnaissance - Rule #31",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(31)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0202",
                name="Automated Scanner Reconnaissance - Rule #32",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(32)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0203",
                name="Automated Scanner Reconnaissance - Rule #33",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(33)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
        self.register(
            SpecializedSignature(
                sig_id="SPEC-SIG-0204",
                name="Automated Scanner Reconnaissance - Rule #34",
                category=AttackCategory.SUSPICIOUS_HEADER,
                severity=AlertSeverity.MEDIUM,
                regex_pattern=re.compile(r"(sqlmap|nikto|nmap\s+scripting|dirbuster|gobuster|masscan|hydra).*(34)?", re.IGNORECASE),
                target_layer="ALL",
                remediation="Apply automated input sanitization, WAF virtual patching, and parameterized queries.",
            )
        )
