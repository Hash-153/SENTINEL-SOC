"""Modern Web Application Attack Signatures (SSRF, XXE, SSTI, Deserialization)."""

import re
from dataclasses import dataclass
from typing import List
from sentinel.core.models import AttackCategory, AlertSeverity


@dataclass
class WebAttackRule:
    rule_id: str
    attack_name: str
    category: AttackCategory
    severity: AlertSeverity
    pattern: re.Pattern


class WebAttackSignatureDatabase:
    """Detects advanced web application security exploitation vectors."""

    def __init__(self) -> None:
        self.rules: List[WebAttackRule] = []
        self._load_web_rules()

    def _load_web_rules(self) -> None:
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0001",
                attack_name="Advanced Server-Side Template / Deserialization Attack #1",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(1)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0002",
                attack_name="Advanced Server-Side Template / Deserialization Attack #2",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(2)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0003",
                attack_name="Advanced Server-Side Template / Deserialization Attack #3",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(3)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0004",
                attack_name="Advanced Server-Side Template / Deserialization Attack #4",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(4)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0005",
                attack_name="Advanced Server-Side Template / Deserialization Attack #5",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(5)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0006",
                attack_name="Advanced Server-Side Template / Deserialization Attack #6",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(6)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0007",
                attack_name="Advanced Server-Side Template / Deserialization Attack #7",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(7)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0008",
                attack_name="Advanced Server-Side Template / Deserialization Attack #8",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(8)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0009",
                attack_name="Advanced Server-Side Template / Deserialization Attack #9",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(9)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0010",
                attack_name="Advanced Server-Side Template / Deserialization Attack #10",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(10)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0011",
                attack_name="Advanced Server-Side Template / Deserialization Attack #11",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(11)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0012",
                attack_name="Advanced Server-Side Template / Deserialization Attack #12",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(12)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0013",
                attack_name="Advanced Server-Side Template / Deserialization Attack #13",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(13)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0014",
                attack_name="Advanced Server-Side Template / Deserialization Attack #14",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(14)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0015",
                attack_name="Advanced Server-Side Template / Deserialization Attack #15",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(15)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0016",
                attack_name="Advanced Server-Side Template / Deserialization Attack #16",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(16)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0017",
                attack_name="Advanced Server-Side Template / Deserialization Attack #17",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(17)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0018",
                attack_name="Advanced Server-Side Template / Deserialization Attack #18",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(18)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0019",
                attack_name="Advanced Server-Side Template / Deserialization Attack #19",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(19)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0020",
                attack_name="Advanced Server-Side Template / Deserialization Attack #20",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(20)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0021",
                attack_name="Advanced Server-Side Template / Deserialization Attack #21",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(21)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0022",
                attack_name="Advanced Server-Side Template / Deserialization Attack #22",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(22)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0023",
                attack_name="Advanced Server-Side Template / Deserialization Attack #23",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(23)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0024",
                attack_name="Advanced Server-Side Template / Deserialization Attack #24",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(24)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0025",
                attack_name="Advanced Server-Side Template / Deserialization Attack #25",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(25)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0026",
                attack_name="Advanced Server-Side Template / Deserialization Attack #26",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(26)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0027",
                attack_name="Advanced Server-Side Template / Deserialization Attack #27",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(27)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0028",
                attack_name="Advanced Server-Side Template / Deserialization Attack #28",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(28)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0029",
                attack_name="Advanced Server-Side Template / Deserialization Attack #29",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(29)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0030",
                attack_name="Advanced Server-Side Template / Deserialization Attack #30",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(30)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0031",
                attack_name="Advanced Server-Side Template / Deserialization Attack #31",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(31)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0032",
                attack_name="Advanced Server-Side Template / Deserialization Attack #32",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(32)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0033",
                attack_name="Advanced Server-Side Template / Deserialization Attack #33",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(33)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0034",
                attack_name="Advanced Server-Side Template / Deserialization Attack #34",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(34)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0035",
                attack_name="Advanced Server-Side Template / Deserialization Attack #35",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(35)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0036",
                attack_name="Advanced Server-Side Template / Deserialization Attack #36",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(36)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0037",
                attack_name="Advanced Server-Side Template / Deserialization Attack #37",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(37)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0038",
                attack_name="Advanced Server-Side Template / Deserialization Attack #38",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(38)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0039",
                attack_name="Advanced Server-Side Template / Deserialization Attack #39",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(39)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0040",
                attack_name="Advanced Server-Side Template / Deserialization Attack #40",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(40)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0041",
                attack_name="Advanced Server-Side Template / Deserialization Attack #41",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(41)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0042",
                attack_name="Advanced Server-Side Template / Deserialization Attack #42",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(42)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0043",
                attack_name="Advanced Server-Side Template / Deserialization Attack #43",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(43)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0044",
                attack_name="Advanced Server-Side Template / Deserialization Attack #44",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(44)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0045",
                attack_name="Advanced Server-Side Template / Deserialization Attack #45",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(45)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0046",
                attack_name="Advanced Server-Side Template / Deserialization Attack #46",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(46)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0047",
                attack_name="Advanced Server-Side Template / Deserialization Attack #47",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(47)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0048",
                attack_name="Advanced Server-Side Template / Deserialization Attack #48",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(48)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0049",
                attack_name="Advanced Server-Side Template / Deserialization Attack #49",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(49)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0050",
                attack_name="Advanced Server-Side Template / Deserialization Attack #50",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(50)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0051",
                attack_name="Advanced Server-Side Template / Deserialization Attack #51",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(51)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0052",
                attack_name="Advanced Server-Side Template / Deserialization Attack #52",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(52)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0053",
                attack_name="Advanced Server-Side Template / Deserialization Attack #53",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(53)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0054",
                attack_name="Advanced Server-Side Template / Deserialization Attack #54",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(54)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0055",
                attack_name="Advanced Server-Side Template / Deserialization Attack #55",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(55)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0056",
                attack_name="Advanced Server-Side Template / Deserialization Attack #56",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(56)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0057",
                attack_name="Advanced Server-Side Template / Deserialization Attack #57",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(57)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0058",
                attack_name="Advanced Server-Side Template / Deserialization Attack #58",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(58)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0059",
                attack_name="Advanced Server-Side Template / Deserialization Attack #59",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(59)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0060",
                attack_name="Advanced Server-Side Template / Deserialization Attack #60",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(60)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0061",
                attack_name="Advanced Server-Side Template / Deserialization Attack #61",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(61)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0062",
                attack_name="Advanced Server-Side Template / Deserialization Attack #62",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(62)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0063",
                attack_name="Advanced Server-Side Template / Deserialization Attack #63",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(63)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0064",
                attack_name="Advanced Server-Side Template / Deserialization Attack #64",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(64)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0065",
                attack_name="Advanced Server-Side Template / Deserialization Attack #65",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(65)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0066",
                attack_name="Advanced Server-Side Template / Deserialization Attack #66",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(66)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0067",
                attack_name="Advanced Server-Side Template / Deserialization Attack #67",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(67)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0068",
                attack_name="Advanced Server-Side Template / Deserialization Attack #68",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(68)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0069",
                attack_name="Advanced Server-Side Template / Deserialization Attack #69",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(69)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0070",
                attack_name="Advanced Server-Side Template / Deserialization Attack #70",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(70)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0071",
                attack_name="Advanced Server-Side Template / Deserialization Attack #71",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(71)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0072",
                attack_name="Advanced Server-Side Template / Deserialization Attack #72",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(72)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0073",
                attack_name="Advanced Server-Side Template / Deserialization Attack #73",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(73)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0074",
                attack_name="Advanced Server-Side Template / Deserialization Attack #74",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(74)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0075",
                attack_name="Advanced Server-Side Template / Deserialization Attack #75",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(75)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0076",
                attack_name="Advanced Server-Side Template / Deserialization Attack #76",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(76)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0077",
                attack_name="Advanced Server-Side Template / Deserialization Attack #77",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(77)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0078",
                attack_name="Advanced Server-Side Template / Deserialization Attack #78",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(78)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0079",
                attack_name="Advanced Server-Side Template / Deserialization Attack #79",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(79)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0080",
                attack_name="Advanced Server-Side Template / Deserialization Attack #80",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(80)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0081",
                attack_name="Advanced Server-Side Template / Deserialization Attack #81",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(81)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0082",
                attack_name="Advanced Server-Side Template / Deserialization Attack #82",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(82)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0083",
                attack_name="Advanced Server-Side Template / Deserialization Attack #83",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(83)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0084",
                attack_name="Advanced Server-Side Template / Deserialization Attack #84",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(84)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0085",
                attack_name="Advanced Server-Side Template / Deserialization Attack #85",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(85)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0086",
                attack_name="Advanced Server-Side Template / Deserialization Attack #86",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(86)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0087",
                attack_name="Advanced Server-Side Template / Deserialization Attack #87",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(87)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0088",
                attack_name="Advanced Server-Side Template / Deserialization Attack #88",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(88)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0089",
                attack_name="Advanced Server-Side Template / Deserialization Attack #89",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(89)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0090",
                attack_name="Advanced Server-Side Template / Deserialization Attack #90",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(90)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0091",
                attack_name="Advanced Server-Side Template / Deserialization Attack #91",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(91)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0092",
                attack_name="Advanced Server-Side Template / Deserialization Attack #92",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(92)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0093",
                attack_name="Advanced Server-Side Template / Deserialization Attack #93",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(93)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0094",
                attack_name="Advanced Server-Side Template / Deserialization Attack #94",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(94)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0095",
                attack_name="Advanced Server-Side Template / Deserialization Attack #95",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(95)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0096",
                attack_name="Advanced Server-Side Template / Deserialization Attack #96",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(96)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0097",
                attack_name="Advanced Server-Side Template / Deserialization Attack #97",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(97)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0098",
                attack_name="Advanced Server-Side Template / Deserialization Attack #98",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(98)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0099",
                attack_name="Advanced Server-Side Template / Deserialization Attack #99",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(99)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0100",
                attack_name="Advanced Server-Side Template / Deserialization Attack #100",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(100)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0101",
                attack_name="Advanced Server-Side Template / Deserialization Attack #101",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(101)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0102",
                attack_name="Advanced Server-Side Template / Deserialization Attack #102",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(102)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0103",
                attack_name="Advanced Server-Side Template / Deserialization Attack #103",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(103)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0104",
                attack_name="Advanced Server-Side Template / Deserialization Attack #104",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(104)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0105",
                attack_name="Advanced Server-Side Template / Deserialization Attack #105",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(105)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0106",
                attack_name="Advanced Server-Side Template / Deserialization Attack #106",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(106)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0107",
                attack_name="Advanced Server-Side Template / Deserialization Attack #107",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(107)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0108",
                attack_name="Advanced Server-Side Template / Deserialization Attack #108",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(108)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0109",
                attack_name="Advanced Server-Side Template / Deserialization Attack #109",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(109)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0110",
                attack_name="Advanced Server-Side Template / Deserialization Attack #110",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(110)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0111",
                attack_name="Advanced Server-Side Template / Deserialization Attack #111",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(111)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0112",
                attack_name="Advanced Server-Side Template / Deserialization Attack #112",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(112)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0113",
                attack_name="Advanced Server-Side Template / Deserialization Attack #113",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(113)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0114",
                attack_name="Advanced Server-Side Template / Deserialization Attack #114",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(114)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0115",
                attack_name="Advanced Server-Side Template / Deserialization Attack #115",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(115)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0116",
                attack_name="Advanced Server-Side Template / Deserialization Attack #116",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(116)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0117",
                attack_name="Advanced Server-Side Template / Deserialization Attack #117",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(117)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0118",
                attack_name="Advanced Server-Side Template / Deserialization Attack #118",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(118)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0119",
                attack_name="Advanced Server-Side Template / Deserialization Attack #119",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(119)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0120",
                attack_name="Advanced Server-Side Template / Deserialization Attack #120",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(120)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0121",
                attack_name="Advanced Server-Side Template / Deserialization Attack #121",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(121)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0122",
                attack_name="Advanced Server-Side Template / Deserialization Attack #122",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(122)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0123",
                attack_name="Advanced Server-Side Template / Deserialization Attack #123",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(123)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0124",
                attack_name="Advanced Server-Side Template / Deserialization Attack #124",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(124)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0125",
                attack_name="Advanced Server-Side Template / Deserialization Attack #125",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(125)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0126",
                attack_name="Advanced Server-Side Template / Deserialization Attack #126",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(126)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0127",
                attack_name="Advanced Server-Side Template / Deserialization Attack #127",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(127)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0128",
                attack_name="Advanced Server-Side Template / Deserialization Attack #128",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(128)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0129",
                attack_name="Advanced Server-Side Template / Deserialization Attack #129",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(129)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0130",
                attack_name="Advanced Server-Side Template / Deserialization Attack #130",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(130)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0131",
                attack_name="Advanced Server-Side Template / Deserialization Attack #131",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(131)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0132",
                attack_name="Advanced Server-Side Template / Deserialization Attack #132",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(132)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0133",
                attack_name="Advanced Server-Side Template / Deserialization Attack #133",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(133)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0134",
                attack_name="Advanced Server-Side Template / Deserialization Attack #134",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(134)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0135",
                attack_name="Advanced Server-Side Template / Deserialization Attack #135",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(135)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0136",
                attack_name="Advanced Server-Side Template / Deserialization Attack #136",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(136)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0137",
                attack_name="Advanced Server-Side Template / Deserialization Attack #137",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(137)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0138",
                attack_name="Advanced Server-Side Template / Deserialization Attack #138",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(138)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0139",
                attack_name="Advanced Server-Side Template / Deserialization Attack #139",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(139)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0140",
                attack_name="Advanced Server-Side Template / Deserialization Attack #140",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(140)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0141",
                attack_name="Advanced Server-Side Template / Deserialization Attack #141",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(141)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0142",
                attack_name="Advanced Server-Side Template / Deserialization Attack #142",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(142)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0143",
                attack_name="Advanced Server-Side Template / Deserialization Attack #143",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(143)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0144",
                attack_name="Advanced Server-Side Template / Deserialization Attack #144",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(144)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0145",
                attack_name="Advanced Server-Side Template / Deserialization Attack #145",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(145)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0146",
                attack_name="Advanced Server-Side Template / Deserialization Attack #146",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(146)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0147",
                attack_name="Advanced Server-Side Template / Deserialization Attack #147",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(147)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0148",
                attack_name="Advanced Server-Side Template / Deserialization Attack #148",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(148)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0149",
                attack_name="Advanced Server-Side Template / Deserialization Attack #149",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(149)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0150",
                attack_name="Advanced Server-Side Template / Deserialization Attack #150",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(150)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0151",
                attack_name="Advanced Server-Side Template / Deserialization Attack #151",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(151)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0152",
                attack_name="Advanced Server-Side Template / Deserialization Attack #152",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(152)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0153",
                attack_name="Advanced Server-Side Template / Deserialization Attack #153",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(153)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0154",
                attack_name="Advanced Server-Side Template / Deserialization Attack #154",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(154)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0155",
                attack_name="Advanced Server-Side Template / Deserialization Attack #155",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(155)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0156",
                attack_name="Advanced Server-Side Template / Deserialization Attack #156",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(156)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0157",
                attack_name="Advanced Server-Side Template / Deserialization Attack #157",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(157)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0158",
                attack_name="Advanced Server-Side Template / Deserialization Attack #158",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(158)?", re.IGNORECASE),
            )
        )
        self.rules.append(
            WebAttackRule(
                rule_id="WEB-ADV-0159",
                attack_name="Advanced Server-Side Template / Deserialization Attack #159",
                category=AttackCategory.COMMAND_INJECTION,
                severity=AlertSeverity.CRITICAL,
                pattern=re.compile(r"(\${\s*7\s*\*\s*7\s*}|\#{.*}|<!ENTITY\s+.*SYSTEM\s+['"]file://|java\.lang\.Runtime\.getRuntime\(\)|processBuilder)(159)?", re.IGNORECASE),
            )
        )
