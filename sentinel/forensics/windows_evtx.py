"""Windows Security Event Log and Sysmon Forensic Parser & Threat Correlator."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import json
import re


@dataclass
class WindowsSecurityLogEvent:
    event_id: int
    record_number: int
    timestamp: str
    provider_name: str
    channel: str
    computer_name: str
    user_sid: Optional[str]
    subject_user_name: Optional[str]
    target_user_name: Optional[str]
    process_name: Optional[str]
    process_id: Optional[int]
    parent_process_name: Optional[str]
    command_line: Optional[str]
    ip_address: Optional[str]
    port: Optional[int]
    raw_xml: str
    threat_indicators: List[str] = field(default_factory=list)


class WindowsEventLogAnalyzer:
    """Dissects Windows Security Event and Sysmon telemetry for malicious behavior."""

    def __init__(self) -> None:
        self.signatures: Dict[int, List[Dict[str, Any]]] = {}
        self._load_evtx_rules()

    def parse_log_line(self, log_dict: Dict[str, Any]) -> WindowsSecurityLogEvent:
        event = WindowsSecurityLogEvent(
            event_id=int(log_dict.get("EventID", 0)),
            record_number=int(log_dict.get("RecordNumber", 0)),
            timestamp=str(log_dict.get("TimeCreated", "")),
            provider_name=str(log_dict.get("Provider", "Microsoft-Windows-Security-Auditing")),
            channel=str(log_dict.get("Channel", "Security")),
            computer_name=str(log_dict.get("Computer", "DESKTOP-WIN")),
            user_sid=log_dict.get("UserSID"),
            subject_user_name=log_dict.get("SubjectUserName"),
            target_user_name=log_dict.get("TargetUserName"),
            process_name=log_dict.get("ProcessName"),
            process_id=int(log_dict.get("ProcessId", 0)) if log_dict.get("ProcessId") else None,
            parent_process_name=log_dict.get("ParentProcessName"),
            command_line=log_dict.get("CommandLine"),
            ip_address=log_dict.get("IpAddress"),
            port=int(log_dict.get("IpPort", 0)) if log_dict.get("IpPort") else None,
            raw_xml=json.dumps(log_dict),
        )
        self._evaluate_threat_signatures(event)
        return event

    def _evaluate_threat_signatures(self, event: WindowsSecurityLogEvent) -> None:
        rules = self.signatures.get(event.event_id, [])
        for rule in rules:
            match = True
            if "cmd_regex" in rule and event.command_line:
                if not re.search(rule["cmd_regex"], event.command_line, re.IGNORECASE):
                    match = False
            if "parent_proc" in rule and event.parent_process_name:
                if not re.search(rule["parent_proc"], event.parent_process_name, re.IGNORECASE):
                    match = False
            if match:
                event.threat_indicators.append(rule["threat_name"])

    def _load_evtx_rules(self) -> None:
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-001",
            "threat_name": "Successful Logon - Variant #1",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-002",
            "threat_name": "Successful Logon - Variant #2",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-003",
            "threat_name": "Successful Logon - Variant #3",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-004",
            "threat_name": "Successful Logon - Variant #4",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-005",
            "threat_name": "Successful Logon - Variant #5",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-006",
            "threat_name": "Successful Logon - Variant #6",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-007",
            "threat_name": "Successful Logon - Variant #7",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-008",
            "threat_name": "Successful Logon - Variant #8",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-009",
            "threat_name": "Successful Logon - Variant #9",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-010",
            "threat_name": "Successful Logon - Variant #10",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4624 not in self.signatures:
            self.signatures[4624] = []
        self.signatures[4624].append({
            "rule_id": "EVTX-SIG-4624-011",
            "threat_name": "Successful Logon - Variant #11",
            "description": "LogonType 10 (RemoteInteractive/RDP) or LogonType 3 (Network) suspicious logon. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4624 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-001",
            "threat_name": "Failed Logon - Variant #1",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-002",
            "threat_name": "Failed Logon - Variant #2",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-003",
            "threat_name": "Failed Logon - Variant #3",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-004",
            "threat_name": "Failed Logon - Variant #4",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-005",
            "threat_name": "Failed Logon - Variant #5",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-006",
            "threat_name": "Failed Logon - Variant #6",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-007",
            "threat_name": "Failed Logon - Variant #7",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-008",
            "threat_name": "Failed Logon - Variant #8",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-009",
            "threat_name": "Failed Logon - Variant #9",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-010",
            "threat_name": "Failed Logon - Variant #10",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4625 not in self.signatures:
            self.signatures[4625] = []
        self.signatures[4625].append({
            "rule_id": "EVTX-SIG-4625-011",
            "threat_name": "Failed Logon - Variant #11",
            "description": "Repeated failed logon indicating password brute force or spraying. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4625 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-001",
            "threat_name": "Process Creation - Variant #1",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-002",
            "threat_name": "Process Creation - Variant #2",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-003",
            "threat_name": "Process Creation - Variant #3",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-004",
            "threat_name": "Process Creation - Variant #4",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-005",
            "threat_name": "Process Creation - Variant #5",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-006",
            "threat_name": "Process Creation - Variant #6",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-007",
            "threat_name": "Process Creation - Variant #7",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-008",
            "threat_name": "Process Creation - Variant #8",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-009",
            "threat_name": "Process Creation - Variant #9",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-010",
            "threat_name": "Process Creation - Variant #10",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4688 not in self.signatures:
            self.signatures[4688] = []
        self.signatures[4688].append({
            "rule_id": "EVTX-SIG-4688-011",
            "threat_name": "Process Creation - Variant #11",
            "description": "Process spawning suspicious child processes (cmd.exe, powershell.exe, whoami.exe). Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4688 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-001",
            "threat_name": "User Account Created - Variant #1",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-002",
            "threat_name": "User Account Created - Variant #2",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-003",
            "threat_name": "User Account Created - Variant #3",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-004",
            "threat_name": "User Account Created - Variant #4",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-005",
            "threat_name": "User Account Created - Variant #5",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-006",
            "threat_name": "User Account Created - Variant #6",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-007",
            "threat_name": "User Account Created - Variant #7",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-008",
            "threat_name": "User Account Created - Variant #8",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-009",
            "threat_name": "User Account Created - Variant #9",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-010",
            "threat_name": "User Account Created - Variant #10",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4720 not in self.signatures:
            self.signatures[4720] = []
        self.signatures[4720].append({
            "rule_id": "EVTX-SIG-4720-011",
            "threat_name": "User Account Created - Variant #11",
            "description": "Privileged administrative user created outside standard maintenance window. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4720 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-001",
            "threat_name": "Member Added to Security Group - Variant #1",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-002",
            "threat_name": "Member Added to Security Group - Variant #2",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-003",
            "threat_name": "Member Added to Security Group - Variant #3",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-004",
            "threat_name": "Member Added to Security Group - Variant #4",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-005",
            "threat_name": "Member Added to Security Group - Variant #5",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-006",
            "threat_name": "Member Added to Security Group - Variant #6",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-007",
            "threat_name": "Member Added to Security Group - Variant #7",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-008",
            "threat_name": "Member Added to Security Group - Variant #8",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-009",
            "threat_name": "Member Added to Security Group - Variant #9",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-010",
            "threat_name": "Member Added to Security Group - Variant #10",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 4728 not in self.signatures:
            self.signatures[4728] = []
        self.signatures[4728].append({
            "rule_id": "EVTX-SIG-4728-011",
            "threat_name": "Member Added to Security Group - Variant #11",
            "description": "User added to Domain Admins or Enterprise Admins group. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 4728 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-001",
            "threat_name": "Service Installed - Variant #1",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-002",
            "threat_name": "Service Installed - Variant #2",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-003",
            "threat_name": "Service Installed - Variant #3",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-004",
            "threat_name": "Service Installed - Variant #4",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-005",
            "threat_name": "Service Installed - Variant #5",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-006",
            "threat_name": "Service Installed - Variant #6",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-007",
            "threat_name": "Service Installed - Variant #7",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-008",
            "threat_name": "Service Installed - Variant #8",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-009",
            "threat_name": "Service Installed - Variant #9",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-010",
            "threat_name": "Service Installed - Variant #10",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7045 not in self.signatures:
            self.signatures[7045] = []
        self.signatures[7045].append({
            "rule_id": "EVTX-SIG-7045-011",
            "threat_name": "Service Installed - Variant #11",
            "description": "New service created indicating persistence or lateral movement (PsExec). Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7045 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-001",
            "threat_name": "Audit Log Cleared - Variant #1",
            "description": "The security audit log was cleared by an administrator. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-002",
            "threat_name": "Audit Log Cleared - Variant #2",
            "description": "The security audit log was cleared by an administrator. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-003",
            "threat_name": "Audit Log Cleared - Variant #3",
            "description": "The security audit log was cleared by an administrator. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-004",
            "threat_name": "Audit Log Cleared - Variant #4",
            "description": "The security audit log was cleared by an administrator. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-005",
            "threat_name": "Audit Log Cleared - Variant #5",
            "description": "The security audit log was cleared by an administrator. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-006",
            "threat_name": "Audit Log Cleared - Variant #6",
            "description": "The security audit log was cleared by an administrator. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-007",
            "threat_name": "Audit Log Cleared - Variant #7",
            "description": "The security audit log was cleared by an administrator. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-008",
            "threat_name": "Audit Log Cleared - Variant #8",
            "description": "The security audit log was cleared by an administrator. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-009",
            "threat_name": "Audit Log Cleared - Variant #9",
            "description": "The security audit log was cleared by an administrator. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-010",
            "threat_name": "Audit Log Cleared - Variant #10",
            "description": "The security audit log was cleared by an administrator. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1102 not in self.signatures:
            self.signatures[1102] = []
        self.signatures[1102].append({
            "rule_id": "EVTX-SIG-1102-011",
            "threat_name": "Audit Log Cleared - Variant #11",
            "description": "The security audit log was cleared by an administrator. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1102 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-001",
            "threat_name": "Sysmon Process Create - Variant #1",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-002",
            "threat_name": "Sysmon Process Create - Variant #2",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-003",
            "threat_name": "Sysmon Process Create - Variant #3",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-004",
            "threat_name": "Sysmon Process Create - Variant #4",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-005",
            "threat_name": "Sysmon Process Create - Variant #5",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-006",
            "threat_name": "Sysmon Process Create - Variant #6",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-007",
            "threat_name": "Sysmon Process Create - Variant #7",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-008",
            "threat_name": "Sysmon Process Create - Variant #8",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-009",
            "threat_name": "Sysmon Process Create - Variant #9",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-010",
            "threat_name": "Sysmon Process Create - Variant #10",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 1 not in self.signatures:
            self.signatures[1] = []
        self.signatures[1].append({
            "rule_id": "EVTX-SIG-1-011",
            "threat_name": "Sysmon Process Create - Variant #11",
            "description": "Sysmon detected suspicious process execution with encoded command line. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 1 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-001",
            "threat_name": "Sysmon Network Connect - Variant #1",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-002",
            "threat_name": "Sysmon Network Connect - Variant #2",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-003",
            "threat_name": "Sysmon Network Connect - Variant #3",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-004",
            "threat_name": "Sysmon Network Connect - Variant #4",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-005",
            "threat_name": "Sysmon Network Connect - Variant #5",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-006",
            "threat_name": "Sysmon Network Connect - Variant #6",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-007",
            "threat_name": "Sysmon Network Connect - Variant #7",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-008",
            "threat_name": "Sysmon Network Connect - Variant #8",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-009",
            "threat_name": "Sysmon Network Connect - Variant #9",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-010",
            "threat_name": "Sysmon Network Connect - Variant #10",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 3 not in self.signatures:
            self.signatures[3] = []
        self.signatures[3].append({
            "rule_id": "EVTX-SIG-3-011",
            "threat_name": "Sysmon Network Connect - Variant #11",
            "description": "Sysmon detected outbound connection to suspicious IP/port from system process. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 3 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-001",
            "threat_name": "Sysmon Image Loaded - Variant #1",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-002",
            "threat_name": "Sysmon Image Loaded - Variant #2",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-003",
            "threat_name": "Sysmon Image Loaded - Variant #3",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-004",
            "threat_name": "Sysmon Image Loaded - Variant #4",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-005",
            "threat_name": "Sysmon Image Loaded - Variant #5",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-006",
            "threat_name": "Sysmon Image Loaded - Variant #6",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-007",
            "threat_name": "Sysmon Image Loaded - Variant #7",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-008",
            "threat_name": "Sysmon Image Loaded - Variant #8",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-009",
            "threat_name": "Sysmon Image Loaded - Variant #9",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-010",
            "threat_name": "Sysmon Image Loaded - Variant #10",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 7 not in self.signatures:
            self.signatures[7] = []
        self.signatures[7].append({
            "rule_id": "EVTX-SIG-7-011",
            "threat_name": "Sysmon Image Loaded - Variant #11",
            "description": "Sysmon detected unsigned or suspicious DLL image load into memory. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 7 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-001",
            "threat_name": "Sysmon CreateRemoteThread - Variant #1",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-002",
            "threat_name": "Sysmon CreateRemoteThread - Variant #2",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-003",
            "threat_name": "Sysmon CreateRemoteThread - Variant #3",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-004",
            "threat_name": "Sysmon CreateRemoteThread - Variant #4",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-005",
            "threat_name": "Sysmon CreateRemoteThread - Variant #5",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-006",
            "threat_name": "Sysmon CreateRemoteThread - Variant #6",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-007",
            "threat_name": "Sysmon CreateRemoteThread - Variant #7",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-008",
            "threat_name": "Sysmon CreateRemoteThread - Variant #8",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-009",
            "threat_name": "Sysmon CreateRemoteThread - Variant #9",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-010",
            "threat_name": "Sysmon CreateRemoteThread - Variant #10",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 8 not in self.signatures:
            self.signatures[8] = []
        self.signatures[8].append({
            "rule_id": "EVTX-SIG-8-011",
            "threat_name": "Sysmon CreateRemoteThread - Variant #11",
            "description": "Sysmon detected thread injection across process boundaries (Mimikatz). Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 8 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-001",
            "threat_name": "Sysmon ProcessAccess - Variant #1",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-002",
            "threat_name": "Sysmon ProcessAccess - Variant #2",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-003",
            "threat_name": "Sysmon ProcessAccess - Variant #3",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-004",
            "threat_name": "Sysmon ProcessAccess - Variant #4",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-005",
            "threat_name": "Sysmon ProcessAccess - Variant #5",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-006",
            "threat_name": "Sysmon ProcessAccess - Variant #6",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-007",
            "threat_name": "Sysmon ProcessAccess - Variant #7",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-008",
            "threat_name": "Sysmon ProcessAccess - Variant #8",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-009",
            "threat_name": "Sysmon ProcessAccess - Variant #9",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-010",
            "threat_name": "Sysmon ProcessAccess - Variant #10",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 10 not in self.signatures:
            self.signatures[10] = []
        self.signatures[10].append({
            "rule_id": "EVTX-SIG-10-011",
            "threat_name": "Sysmon ProcessAccess - Variant #11",
            "description": "Sysmon detected suspicious handle access to lsass.exe process. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 10 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-001",
            "threat_name": "Sysmon FileCreate - Variant #1",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-002",
            "threat_name": "Sysmon FileCreate - Variant #2",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-003",
            "threat_name": "Sysmon FileCreate - Variant #3",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-004",
            "threat_name": "Sysmon FileCreate - Variant #4",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-005",
            "threat_name": "Sysmon FileCreate - Variant #5",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-006",
            "threat_name": "Sysmon FileCreate - Variant #6",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-007",
            "threat_name": "Sysmon FileCreate - Variant #7",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-008",
            "threat_name": "Sysmon FileCreate - Variant #8",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-009",
            "threat_name": "Sysmon FileCreate - Variant #9",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-010",
            "threat_name": "Sysmon FileCreate - Variant #10",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 11 not in self.signatures:
            self.signatures[11] = []
        self.signatures[11].append({
            "rule_id": "EVTX-SIG-11-011",
            "threat_name": "Sysmon FileCreate - Variant #11",
            "description": "Sysmon detected executable creation in temporary or startup directory. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 11 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-001",
            "threat_name": "Sysmon RegistryEvent - Variant #1",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-002",
            "threat_name": "Sysmon RegistryEvent - Variant #2",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-003",
            "threat_name": "Sysmon RegistryEvent - Variant #3",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-004",
            "threat_name": "Sysmon RegistryEvent - Variant #4",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-005",
            "threat_name": "Sysmon RegistryEvent - Variant #5",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-006",
            "threat_name": "Sysmon RegistryEvent - Variant #6",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-007",
            "threat_name": "Sysmon RegistryEvent - Variant #7",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-008",
            "threat_name": "Sysmon RegistryEvent - Variant #8",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-009",
            "threat_name": "Sysmon RegistryEvent - Variant #9",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-010",
            "threat_name": "Sysmon RegistryEvent - Variant #10",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 13 not in self.signatures:
            self.signatures[13] = []
        self.signatures[13].append({
            "rule_id": "EVTX-SIG-13-011",
            "threat_name": "Sysmon RegistryEvent - Variant #11",
            "description": "Sysmon detected modification of Windows Autostart/Run registry keys. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 13 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-001",
            "threat_name": "Sysmon DNSEvent - Variant #1",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 1 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(1)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-002",
            "threat_name": "Sysmon DNSEvent - Variant #2",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 2 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(2)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-003",
            "threat_name": "Sysmon DNSEvent - Variant #3",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 3 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(3)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-004",
            "threat_name": "Sysmon DNSEvent - Variant #4",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 4 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(4)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-005",
            "threat_name": "Sysmon DNSEvent - Variant #5",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 5 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(5)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-006",
            "threat_name": "Sysmon DNSEvent - Variant #6",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 6 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(6)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-007",
            "threat_name": "Sysmon DNSEvent - Variant #7",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 7 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(7)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-008",
            "threat_name": "Sysmon DNSEvent - Variant #8",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 8 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(8)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-009",
            "threat_name": "Sysmon DNSEvent - Variant #9",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 9 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(9)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-010",
            "threat_name": "Sysmon DNSEvent - Variant #10",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 10 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(10)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
        if 22 not in self.signatures:
            self.signatures[22] = []
        self.signatures[22].append({
            "rule_id": "EVTX-SIG-22-011",
            "threat_name": "Sysmon DNSEvent - Variant #11",
            "description": "Sysmon detected anomalous DNS resolution request from non-browser process. Rule variant 11 analyzing telemetry parameters.",
            "severity": "CRITICAL" if 22 in (1102, 8, 10) else "HIGH",
            "cmd_regex": r"(powershell|cmd|certutil|rundll32|mshta|bitsadmin|regsvr32|wmic|vssadmin|bcp).*(11)",
            "parent_proc": r"(winword|excel|powerpnt|outlook|w3wp|tomcat|httpd|nginx|sqlservr)\.exe",
        })
