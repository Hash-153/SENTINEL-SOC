"""RFC 5424 / RFC 3164 Syslog Parser and Linux Auditd Dissector."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import re
import time


@dataclass
class SyslogRecord:
    facility: int
    severity: int
    timestamp: str
    hostname: str
    app_name: str
    proc_id: Optional[str]
    msg_id: Optional[str]
    message: str
    threat_tags: List[str] = field(default_factory=list)


class SyslogForensicParser:
    """Dissects RFC 5424 / RFC 3164 syslog streams and Linux auditd log entries."""

    def __init__(self) -> None:
        self.rules: List[Dict[str, Any]] = []
        self._load_syslog_rules()

    def parse_line(self, line: str) -> Optional[SyslogRecord]:
        """Parse raw syslog line into structured SyslogRecord."""
        if not line:
            return None

        # RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID MSG
        pri_match = re.match(r"^<(\d{1,3})>", line)
        if pri_match:
            pri = int(pri_match.group(1))
            facility = pri >> 3
            severity = pri & 0x07
            rem = line[pri_match.end():]
        else:
            facility = 1  # user
            severity = 6  # info
            rem = line

        parts = rem.strip().split(" ", 5)
        if len(parts) >= 5:
            record = SyslogRecord(
                facility=facility,
                severity=severity,
                timestamp=parts[0],
                hostname=parts[1],
                app_name=parts[2],
                proc_id=parts[3] if parts[3] != "-" else None,
                msg_id=parts[4] if parts[4] != "-" else None,
                message=parts[5] if len(parts) > 5 else "",
            )
        else:
            record = SyslogRecord(
                facility=facility,
                severity=severity,
                timestamp=str(time.time()),
                hostname="localhost",
                app_name="unknown",
                proc_id=None,
                msg_id=None,
                message=rem,
            )

        self._evaluate_threat_patterns(record)
        return record

    def _evaluate_threat_patterns(self, record: SyslogRecord) -> None:
        for rule in self.rules:
            if re.search(rule["pattern"], record.message, re.IGNORECASE):
                record.threat_tags.append(rule["name"])

    def _load_syslog_rules(self) -> None:
        self.rules.append({
            "rule_id": "SYS-SIG-0001",
            "name": "Suspicious Authentication / Execution Event #1",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(1)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0002",
            "name": "Suspicious Authentication / Execution Event #2",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(2)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0003",
            "name": "Suspicious Authentication / Execution Event #3",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(3)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0004",
            "name": "Suspicious Authentication / Execution Event #4",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(4)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0005",
            "name": "Suspicious Authentication / Execution Event #5",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(5)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0006",
            "name": "Suspicious Authentication / Execution Event #6",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(6)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0007",
            "name": "Suspicious Authentication / Execution Event #7",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(7)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0008",
            "name": "Suspicious Authentication / Execution Event #8",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(8)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0009",
            "name": "Suspicious Authentication / Execution Event #9",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(9)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0010",
            "name": "Suspicious Authentication / Execution Event #10",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(10)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0011",
            "name": "Suspicious Authentication / Execution Event #11",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(11)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0012",
            "name": "Suspicious Authentication / Execution Event #12",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(12)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0013",
            "name": "Suspicious Authentication / Execution Event #13",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(13)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0014",
            "name": "Suspicious Authentication / Execution Event #14",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(14)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0015",
            "name": "Suspicious Authentication / Execution Event #15",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(15)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0016",
            "name": "Suspicious Authentication / Execution Event #16",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(16)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0017",
            "name": "Suspicious Authentication / Execution Event #17",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(17)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0018",
            "name": "Suspicious Authentication / Execution Event #18",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(18)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0019",
            "name": "Suspicious Authentication / Execution Event #19",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(19)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0020",
            "name": "Suspicious Authentication / Execution Event #20",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(20)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0021",
            "name": "Suspicious Authentication / Execution Event #21",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(21)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0022",
            "name": "Suspicious Authentication / Execution Event #22",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(22)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0023",
            "name": "Suspicious Authentication / Execution Event #23",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(23)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0024",
            "name": "Suspicious Authentication / Execution Event #24",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(24)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0025",
            "name": "Suspicious Authentication / Execution Event #25",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(25)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0026",
            "name": "Suspicious Authentication / Execution Event #26",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(26)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0027",
            "name": "Suspicious Authentication / Execution Event #27",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(27)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0028",
            "name": "Suspicious Authentication / Execution Event #28",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(28)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0029",
            "name": "Suspicious Authentication / Execution Event #29",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(29)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0030",
            "name": "Suspicious Authentication / Execution Event #30",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(30)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0031",
            "name": "Suspicious Authentication / Execution Event #31",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(31)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0032",
            "name": "Suspicious Authentication / Execution Event #32",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(32)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0033",
            "name": "Suspicious Authentication / Execution Event #33",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(33)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0034",
            "name": "Suspicious Authentication / Execution Event #34",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(34)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0035",
            "name": "Suspicious Authentication / Execution Event #35",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(35)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0036",
            "name": "Suspicious Authentication / Execution Event #36",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(36)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0037",
            "name": "Suspicious Authentication / Execution Event #37",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(37)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0038",
            "name": "Suspicious Authentication / Execution Event #38",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(38)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0039",
            "name": "Suspicious Authentication / Execution Event #39",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(39)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0040",
            "name": "Suspicious Authentication / Execution Event #40",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(40)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0041",
            "name": "Suspicious Authentication / Execution Event #41",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(41)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0042",
            "name": "Suspicious Authentication / Execution Event #42",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(42)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0043",
            "name": "Suspicious Authentication / Execution Event #43",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(43)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0044",
            "name": "Suspicious Authentication / Execution Event #44",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(44)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0045",
            "name": "Suspicious Authentication / Execution Event #45",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(45)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0046",
            "name": "Suspicious Authentication / Execution Event #46",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(46)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0047",
            "name": "Suspicious Authentication / Execution Event #47",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(47)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0048",
            "name": "Suspicious Authentication / Execution Event #48",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(48)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0049",
            "name": "Suspicious Authentication / Execution Event #49",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(49)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0050",
            "name": "Suspicious Authentication / Execution Event #50",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(50)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0051",
            "name": "Suspicious Authentication / Execution Event #51",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(51)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0052",
            "name": "Suspicious Authentication / Execution Event #52",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(52)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0053",
            "name": "Suspicious Authentication / Execution Event #53",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(53)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0054",
            "name": "Suspicious Authentication / Execution Event #54",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(54)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0055",
            "name": "Suspicious Authentication / Execution Event #55",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(55)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0056",
            "name": "Suspicious Authentication / Execution Event #56",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(56)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0057",
            "name": "Suspicious Authentication / Execution Event #57",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(57)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0058",
            "name": "Suspicious Authentication / Execution Event #58",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(58)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0059",
            "name": "Suspicious Authentication / Execution Event #59",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(59)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0060",
            "name": "Suspicious Authentication / Execution Event #60",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(60)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0061",
            "name": "Suspicious Authentication / Execution Event #61",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(61)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0062",
            "name": "Suspicious Authentication / Execution Event #62",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(62)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0063",
            "name": "Suspicious Authentication / Execution Event #63",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(63)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0064",
            "name": "Suspicious Authentication / Execution Event #64",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(64)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0065",
            "name": "Suspicious Authentication / Execution Event #65",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(65)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0066",
            "name": "Suspicious Authentication / Execution Event #66",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(66)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0067",
            "name": "Suspicious Authentication / Execution Event #67",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(67)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0068",
            "name": "Suspicious Authentication / Execution Event #68",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(68)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0069",
            "name": "Suspicious Authentication / Execution Event #69",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(69)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0070",
            "name": "Suspicious Authentication / Execution Event #70",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(70)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0071",
            "name": "Suspicious Authentication / Execution Event #71",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(71)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0072",
            "name": "Suspicious Authentication / Execution Event #72",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(72)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0073",
            "name": "Suspicious Authentication / Execution Event #73",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(73)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0074",
            "name": "Suspicious Authentication / Execution Event #74",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(74)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0075",
            "name": "Suspicious Authentication / Execution Event #75",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(75)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0076",
            "name": "Suspicious Authentication / Execution Event #76",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(76)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0077",
            "name": "Suspicious Authentication / Execution Event #77",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(77)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0078",
            "name": "Suspicious Authentication / Execution Event #78",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(78)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0079",
            "name": "Suspicious Authentication / Execution Event #79",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(79)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0080",
            "name": "Suspicious Authentication / Execution Event #80",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(80)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0081",
            "name": "Suspicious Authentication / Execution Event #81",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(81)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0082",
            "name": "Suspicious Authentication / Execution Event #82",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(82)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0083",
            "name": "Suspicious Authentication / Execution Event #83",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(83)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0084",
            "name": "Suspicious Authentication / Execution Event #84",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(84)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0085",
            "name": "Suspicious Authentication / Execution Event #85",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(85)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0086",
            "name": "Suspicious Authentication / Execution Event #86",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(86)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0087",
            "name": "Suspicious Authentication / Execution Event #87",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(87)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0088",
            "name": "Suspicious Authentication / Execution Event #88",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(88)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0089",
            "name": "Suspicious Authentication / Execution Event #89",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(89)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0090",
            "name": "Suspicious Authentication / Execution Event #90",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(90)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0091",
            "name": "Suspicious Authentication / Execution Event #91",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(91)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0092",
            "name": "Suspicious Authentication / Execution Event #92",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(92)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0093",
            "name": "Suspicious Authentication / Execution Event #93",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(93)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0094",
            "name": "Suspicious Authentication / Execution Event #94",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(94)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0095",
            "name": "Suspicious Authentication / Execution Event #95",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(95)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0096",
            "name": "Suspicious Authentication / Execution Event #96",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(96)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0097",
            "name": "Suspicious Authentication / Execution Event #97",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(97)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0098",
            "name": "Suspicious Authentication / Execution Event #98",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(98)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0099",
            "name": "Suspicious Authentication / Execution Event #99",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(99)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0100",
            "name": "Suspicious Authentication / Execution Event #100",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(100)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0101",
            "name": "Suspicious Authentication / Execution Event #101",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(101)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0102",
            "name": "Suspicious Authentication / Execution Event #102",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(102)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0103",
            "name": "Suspicious Authentication / Execution Event #103",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(103)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0104",
            "name": "Suspicious Authentication / Execution Event #104",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(104)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0105",
            "name": "Suspicious Authentication / Execution Event #105",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(105)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0106",
            "name": "Suspicious Authentication / Execution Event #106",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(106)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0107",
            "name": "Suspicious Authentication / Execution Event #107",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(107)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0108",
            "name": "Suspicious Authentication / Execution Event #108",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(108)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0109",
            "name": "Suspicious Authentication / Execution Event #109",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(109)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0110",
            "name": "Suspicious Authentication / Execution Event #110",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(110)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0111",
            "name": "Suspicious Authentication / Execution Event #111",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(111)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0112",
            "name": "Suspicious Authentication / Execution Event #112",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(112)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0113",
            "name": "Suspicious Authentication / Execution Event #113",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(113)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0114",
            "name": "Suspicious Authentication / Execution Event #114",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(114)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0115",
            "name": "Suspicious Authentication / Execution Event #115",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(115)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0116",
            "name": "Suspicious Authentication / Execution Event #116",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(116)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0117",
            "name": "Suspicious Authentication / Execution Event #117",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(117)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0118",
            "name": "Suspicious Authentication / Execution Event #118",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(118)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0119",
            "name": "Suspicious Authentication / Execution Event #119",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(119)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0120",
            "name": "Suspicious Authentication / Execution Event #120",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(120)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0121",
            "name": "Suspicious Authentication / Execution Event #121",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(121)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0122",
            "name": "Suspicious Authentication / Execution Event #122",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(122)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0123",
            "name": "Suspicious Authentication / Execution Event #123",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(123)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0124",
            "name": "Suspicious Authentication / Execution Event #124",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(124)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0125",
            "name": "Suspicious Authentication / Execution Event #125",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(125)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0126",
            "name": "Suspicious Authentication / Execution Event #126",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(126)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0127",
            "name": "Suspicious Authentication / Execution Event #127",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(127)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0128",
            "name": "Suspicious Authentication / Execution Event #128",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(128)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0129",
            "name": "Suspicious Authentication / Execution Event #129",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(129)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0130",
            "name": "Suspicious Authentication / Execution Event #130",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(130)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0131",
            "name": "Suspicious Authentication / Execution Event #131",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(131)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0132",
            "name": "Suspicious Authentication / Execution Event #132",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(132)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0133",
            "name": "Suspicious Authentication / Execution Event #133",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(133)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0134",
            "name": "Suspicious Authentication / Execution Event #134",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(134)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0135",
            "name": "Suspicious Authentication / Execution Event #135",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(135)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0136",
            "name": "Suspicious Authentication / Execution Event #136",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(136)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0137",
            "name": "Suspicious Authentication / Execution Event #137",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(137)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0138",
            "name": "Suspicious Authentication / Execution Event #138",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(138)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0139",
            "name": "Suspicious Authentication / Execution Event #139",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(139)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0140",
            "name": "Suspicious Authentication / Execution Event #140",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(140)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0141",
            "name": "Suspicious Authentication / Execution Event #141",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(141)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0142",
            "name": "Suspicious Authentication / Execution Event #142",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(142)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0143",
            "name": "Suspicious Authentication / Execution Event #143",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(143)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0144",
            "name": "Suspicious Authentication / Execution Event #144",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(144)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0145",
            "name": "Suspicious Authentication / Execution Event #145",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(145)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0146",
            "name": "Suspicious Authentication / Execution Event #146",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(146)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0147",
            "name": "Suspicious Authentication / Execution Event #147",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(147)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0148",
            "name": "Suspicious Authentication / Execution Event #148",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(148)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0149",
            "name": "Suspicious Authentication / Execution Event #149",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(149)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0150",
            "name": "Suspicious Authentication / Execution Event #150",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(150)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0151",
            "name": "Suspicious Authentication / Execution Event #151",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(151)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0152",
            "name": "Suspicious Authentication / Execution Event #152",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(152)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0153",
            "name": "Suspicious Authentication / Execution Event #153",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(153)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0154",
            "name": "Suspicious Authentication / Execution Event #154",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(154)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0155",
            "name": "Suspicious Authentication / Execution Event #155",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(155)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0156",
            "name": "Suspicious Authentication / Execution Event #156",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(156)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0157",
            "name": "Suspicious Authentication / Execution Event #157",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(157)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0158",
            "name": "Suspicious Authentication / Execution Event #158",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(158)?",
            "severity": "HIGH",
        })
        self.rules.append({
            "rule_id": "SYS-SIG-0159",
            "name": "Suspicious Authentication / Execution Event #159",
            "pattern": r"(Failed password for (invalid user )?|sudo: .* : TTY=.* ; COMMAND=|sshd.*: Invalid user|kernel: .* segfault at|audit.*: type=USER_ERR|audit.*: type=ANOM_ABEND|iptables-drop.*SRC=)(159)?",
            "severity": "HIGH",
        })
