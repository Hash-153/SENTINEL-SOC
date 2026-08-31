"""Center for Internet Security (CIS) Controls v8 Benchmark Assessment Suite."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class CisControl:
    control_id: str
    title: str
    asset_type: str
    security_function: str
    ig1: bool  # Implementation Group 1
    ig2: bool  # Implementation Group 2
    ig3: bool  # Implementation Group 3
    description: str
    audit_procedure: List[str]
    remediation_procedure: List[str]


class CisBenchmarkEngine:
    """Evaluates enterprise defenses against the 18 CIS Critical Security Controls v8."""

    def __init__(self) -> None:
        self.controls: Dict[str, CisControl] = {}
        self._load_cis_controls()

    def register(self, ctrl: CisControl) -> None:
        self.controls[ctrl.control_id] = ctrl

    def _load_cis_controls(self) -> None:
        self.register(
            CisControl(
                control_id="CIS-1.1",
                title="Inventory and Control of Enterprise Assets - Sub-Control #1",
                asset_type="Devices",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-1.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-1.2",
                title="Inventory and Control of Enterprise Assets - Sub-Control #2",
                asset_type="Devices",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-1.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-1.3",
                title="Inventory and Control of Enterprise Assets - Sub-Control #3",
                asset_type="Devices",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-1.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-1.4",
                title="Inventory and Control of Enterprise Assets - Sub-Control #4",
                asset_type="Devices",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-1.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-1.5",
                title="Inventory and Control of Enterprise Assets - Sub-Control #5",
                asset_type="Devices",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-1.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-1.6",
                title="Inventory and Control of Enterprise Assets - Sub-Control #6",
                asset_type="Devices",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-1.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-1.7",
                title="Inventory and Control of Enterprise Assets - Sub-Control #7",
                asset_type="Devices",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-1.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-1.8",
                title="Inventory and Control of Enterprise Assets - Sub-Control #8",
                asset_type="Devices",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-1.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-1.9",
                title="Inventory and Control of Enterprise Assets - Sub-Control #9",
                asset_type="Devices",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-1.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-1.10",
                title="Inventory and Control of Enterprise Assets - Sub-Control #10",
                asset_type="Devices",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-1.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-1.11",
                title="Inventory and Control of Enterprise Assets - Sub-Control #11",
                asset_type="Devices",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-1.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.1",
                title="Inventory and Control of Software Assets - Sub-Control #1",
                asset_type="Applications",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-2.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.2",
                title="Inventory and Control of Software Assets - Sub-Control #2",
                asset_type="Applications",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-2.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.3",
                title="Inventory and Control of Software Assets - Sub-Control #3",
                asset_type="Applications",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-2.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.4",
                title="Inventory and Control of Software Assets - Sub-Control #4",
                asset_type="Applications",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-2.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.5",
                title="Inventory and Control of Software Assets - Sub-Control #5",
                asset_type="Applications",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-2.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.6",
                title="Inventory and Control of Software Assets - Sub-Control #6",
                asset_type="Applications",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-2.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.7",
                title="Inventory and Control of Software Assets - Sub-Control #7",
                asset_type="Applications",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-2.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.8",
                title="Inventory and Control of Software Assets - Sub-Control #8",
                asset_type="Applications",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-2.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.9",
                title="Inventory and Control of Software Assets - Sub-Control #9",
                asset_type="Applications",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-2.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.10",
                title="Inventory and Control of Software Assets - Sub-Control #10",
                asset_type="Applications",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-2.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-2.11",
                title="Inventory and Control of Software Assets - Sub-Control #11",
                asset_type="Applications",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-2.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.1",
                title="Data Protection - Sub-Control #1",
                asset_type="Data",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-3.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.2",
                title="Data Protection - Sub-Control #2",
                asset_type="Data",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-3.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.3",
                title="Data Protection - Sub-Control #3",
                asset_type="Data",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-3.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.4",
                title="Data Protection - Sub-Control #4",
                asset_type="Data",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-3.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.5",
                title="Data Protection - Sub-Control #5",
                asset_type="Data",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-3.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.6",
                title="Data Protection - Sub-Control #6",
                asset_type="Data",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-3.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.7",
                title="Data Protection - Sub-Control #7",
                asset_type="Data",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-3.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.8",
                title="Data Protection - Sub-Control #8",
                asset_type="Data",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-3.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.9",
                title="Data Protection - Sub-Control #9",
                asset_type="Data",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-3.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.10",
                title="Data Protection - Sub-Control #10",
                asset_type="Data",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-3.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-3.11",
                title="Data Protection - Sub-Control #11",
                asset_type="Data",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-3.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.1",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #1",
                asset_type="Configurations",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-4.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.2",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #2",
                asset_type="Configurations",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-4.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.3",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #3",
                asset_type="Configurations",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-4.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.4",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #4",
                asset_type="Configurations",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-4.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.5",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #5",
                asset_type="Configurations",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-4.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.6",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #6",
                asset_type="Configurations",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-4.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.7",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #7",
                asset_type="Configurations",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-4.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.8",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #8",
                asset_type="Configurations",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-4.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.9",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #9",
                asset_type="Configurations",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-4.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.10",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #10",
                asset_type="Configurations",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-4.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-4.11",
                title="Secure Configuration of Enterprise Assets and Software - Sub-Control #11",
                asset_type="Configurations",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-4.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.1",
                title="Account Management - Sub-Control #1",
                asset_type="Users",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-5.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.2",
                title="Account Management - Sub-Control #2",
                asset_type="Users",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-5.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.3",
                title="Account Management - Sub-Control #3",
                asset_type="Users",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-5.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.4",
                title="Account Management - Sub-Control #4",
                asset_type="Users",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-5.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.5",
                title="Account Management - Sub-Control #5",
                asset_type="Users",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-5.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.6",
                title="Account Management - Sub-Control #6",
                asset_type="Users",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-5.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.7",
                title="Account Management - Sub-Control #7",
                asset_type="Users",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-5.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.8",
                title="Account Management - Sub-Control #8",
                asset_type="Users",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-5.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.9",
                title="Account Management - Sub-Control #9",
                asset_type="Users",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-5.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.10",
                title="Account Management - Sub-Control #10",
                asset_type="Users",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-5.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-5.11",
                title="Account Management - Sub-Control #11",
                asset_type="Users",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-5.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.1",
                title="Access Control Management - Sub-Control #1",
                asset_type="Permissions",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-6.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.2",
                title="Access Control Management - Sub-Control #2",
                asset_type="Permissions",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-6.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.3",
                title="Access Control Management - Sub-Control #3",
                asset_type="Permissions",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-6.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.4",
                title="Access Control Management - Sub-Control #4",
                asset_type="Permissions",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-6.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.5",
                title="Access Control Management - Sub-Control #5",
                asset_type="Permissions",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-6.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.6",
                title="Access Control Management - Sub-Control #6",
                asset_type="Permissions",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-6.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.7",
                title="Access Control Management - Sub-Control #7",
                asset_type="Permissions",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-6.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.8",
                title="Access Control Management - Sub-Control #8",
                asset_type="Permissions",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-6.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.9",
                title="Access Control Management - Sub-Control #9",
                asset_type="Permissions",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-6.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.10",
                title="Access Control Management - Sub-Control #10",
                asset_type="Permissions",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-6.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-6.11",
                title="Access Control Management - Sub-Control #11",
                asset_type="Permissions",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-6.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.1",
                title="Continuous Vulnerability Management - Sub-Control #1",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-7.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.2",
                title="Continuous Vulnerability Management - Sub-Control #2",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-7.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.3",
                title="Continuous Vulnerability Management - Sub-Control #3",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-7.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.4",
                title="Continuous Vulnerability Management - Sub-Control #4",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-7.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.5",
                title="Continuous Vulnerability Management - Sub-Control #5",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-7.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.6",
                title="Continuous Vulnerability Management - Sub-Control #6",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-7.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.7",
                title="Continuous Vulnerability Management - Sub-Control #7",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-7.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.8",
                title="Continuous Vulnerability Management - Sub-Control #8",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-7.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.9",
                title="Continuous Vulnerability Management - Sub-Control #9",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-7.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.10",
                title="Continuous Vulnerability Management - Sub-Control #10",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-7.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-7.11",
                title="Continuous Vulnerability Management - Sub-Control #11",
                asset_type="Vulnerabilities",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-7.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.1",
                title="Audit Log Management - Sub-Control #1",
                asset_type="Logs",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-8.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.2",
                title="Audit Log Management - Sub-Control #2",
                asset_type="Logs",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-8.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.3",
                title="Audit Log Management - Sub-Control #3",
                asset_type="Logs",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-8.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.4",
                title="Audit Log Management - Sub-Control #4",
                asset_type="Logs",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-8.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.5",
                title="Audit Log Management - Sub-Control #5",
                asset_type="Logs",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-8.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.6",
                title="Audit Log Management - Sub-Control #6",
                asset_type="Logs",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-8.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.7",
                title="Audit Log Management - Sub-Control #7",
                asset_type="Logs",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-8.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.8",
                title="Audit Log Management - Sub-Control #8",
                asset_type="Logs",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-8.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.9",
                title="Audit Log Management - Sub-Control #9",
                asset_type="Logs",
                security_function="Detect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-8.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.10",
                title="Audit Log Management - Sub-Control #10",
                asset_type="Logs",
                security_function="Detect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-8.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-8.11",
                title="Audit Log Management - Sub-Control #11",
                asset_type="Logs",
                security_function="Detect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-8.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.1",
                title="Email and Web Browser Protections - Sub-Control #1",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-9.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.2",
                title="Email and Web Browser Protections - Sub-Control #2",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-9.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.3",
                title="Email and Web Browser Protections - Sub-Control #3",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-9.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.4",
                title="Email and Web Browser Protections - Sub-Control #4",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-9.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.5",
                title="Email and Web Browser Protections - Sub-Control #5",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-9.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.6",
                title="Email and Web Browser Protections - Sub-Control #6",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-9.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.7",
                title="Email and Web Browser Protections - Sub-Control #7",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-9.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.8",
                title="Email and Web Browser Protections - Sub-Control #8",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-9.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.9",
                title="Email and Web Browser Protections - Sub-Control #9",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-9.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.10",
                title="Email and Web Browser Protections - Sub-Control #10",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-9.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-9.11",
                title="Email and Web Browser Protections - Sub-Control #11",
                asset_type="Endpoints",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-9.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.1",
                title="Malware Defenses - Sub-Control #1",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-10.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.2",
                title="Malware Defenses - Sub-Control #2",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-10.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.3",
                title="Malware Defenses - Sub-Control #3",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-10.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.4",
                title="Malware Defenses - Sub-Control #4",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-10.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.5",
                title="Malware Defenses - Sub-Control #5",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-10.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.6",
                title="Malware Defenses - Sub-Control #6",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-10.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.7",
                title="Malware Defenses - Sub-Control #7",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-10.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.8",
                title="Malware Defenses - Sub-Control #8",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-10.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.9",
                title="Malware Defenses - Sub-Control #9",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-10.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.10",
                title="Malware Defenses - Sub-Control #10",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-10.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-10.11",
                title="Malware Defenses - Sub-Control #11",
                asset_type="Endpoints",
                security_function="Detect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-10.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.1",
                title="Data Recovery - Sub-Control #1",
                asset_type="Backups",
                security_function="Recover",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-11.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.2",
                title="Data Recovery - Sub-Control #2",
                asset_type="Backups",
                security_function="Recover",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-11.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.3",
                title="Data Recovery - Sub-Control #3",
                asset_type="Backups",
                security_function="Recover",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-11.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.4",
                title="Data Recovery - Sub-Control #4",
                asset_type="Backups",
                security_function="Recover",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-11.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.5",
                title="Data Recovery - Sub-Control #5",
                asset_type="Backups",
                security_function="Recover",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-11.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.6",
                title="Data Recovery - Sub-Control #6",
                asset_type="Backups",
                security_function="Recover",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-11.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.7",
                title="Data Recovery - Sub-Control #7",
                asset_type="Backups",
                security_function="Recover",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-11.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.8",
                title="Data Recovery - Sub-Control #8",
                asset_type="Backups",
                security_function="Recover",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-11.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.9",
                title="Data Recovery - Sub-Control #9",
                asset_type="Backups",
                security_function="Recover",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-11.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.10",
                title="Data Recovery - Sub-Control #10",
                asset_type="Backups",
                security_function="Recover",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-11.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-11.11",
                title="Data Recovery - Sub-Control #11",
                asset_type="Backups",
                security_function="Recover",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-11.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.1",
                title="Network Infrastructure Management - Sub-Control #1",
                asset_type="Network",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-12.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.2",
                title="Network Infrastructure Management - Sub-Control #2",
                asset_type="Network",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-12.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.3",
                title="Network Infrastructure Management - Sub-Control #3",
                asset_type="Network",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-12.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.4",
                title="Network Infrastructure Management - Sub-Control #4",
                asset_type="Network",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-12.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.5",
                title="Network Infrastructure Management - Sub-Control #5",
                asset_type="Network",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-12.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.6",
                title="Network Infrastructure Management - Sub-Control #6",
                asset_type="Network",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-12.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.7",
                title="Network Infrastructure Management - Sub-Control #7",
                asset_type="Network",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-12.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.8",
                title="Network Infrastructure Management - Sub-Control #8",
                asset_type="Network",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-12.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.9",
                title="Network Infrastructure Management - Sub-Control #9",
                asset_type="Network",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-12.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.10",
                title="Network Infrastructure Management - Sub-Control #10",
                asset_type="Network",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-12.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-12.11",
                title="Network Infrastructure Management - Sub-Control #11",
                asset_type="Network",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-12.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.1",
                title="Network Monitoring and Defense - Sub-Control #1",
                asset_type="Network",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-13.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.2",
                title="Network Monitoring and Defense - Sub-Control #2",
                asset_type="Network",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-13.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.3",
                title="Network Monitoring and Defense - Sub-Control #3",
                asset_type="Network",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-13.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.4",
                title="Network Monitoring and Defense - Sub-Control #4",
                asset_type="Network",
                security_function="Detect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-13.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.5",
                title="Network Monitoring and Defense - Sub-Control #5",
                asset_type="Network",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-13.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.6",
                title="Network Monitoring and Defense - Sub-Control #6",
                asset_type="Network",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-13.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.7",
                title="Network Monitoring and Defense - Sub-Control #7",
                asset_type="Network",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-13.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.8",
                title="Network Monitoring and Defense - Sub-Control #8",
                asset_type="Network",
                security_function="Detect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-13.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.9",
                title="Network Monitoring and Defense - Sub-Control #9",
                asset_type="Network",
                security_function="Detect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-13.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.10",
                title="Network Monitoring and Defense - Sub-Control #10",
                asset_type="Network",
                security_function="Detect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-13.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-13.11",
                title="Network Monitoring and Defense - Sub-Control #11",
                asset_type="Network",
                security_function="Detect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-13.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.1",
                title="Security Awareness and Skills Training - Sub-Control #1",
                asset_type="Personnel",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-14.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.2",
                title="Security Awareness and Skills Training - Sub-Control #2",
                asset_type="Personnel",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-14.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.3",
                title="Security Awareness and Skills Training - Sub-Control #3",
                asset_type="Personnel",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-14.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.4",
                title="Security Awareness and Skills Training - Sub-Control #4",
                asset_type="Personnel",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-14.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.5",
                title="Security Awareness and Skills Training - Sub-Control #5",
                asset_type="Personnel",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-14.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.6",
                title="Security Awareness and Skills Training - Sub-Control #6",
                asset_type="Personnel",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-14.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.7",
                title="Security Awareness and Skills Training - Sub-Control #7",
                asset_type="Personnel",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-14.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.8",
                title="Security Awareness and Skills Training - Sub-Control #8",
                asset_type="Personnel",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-14.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.9",
                title="Security Awareness and Skills Training - Sub-Control #9",
                asset_type="Personnel",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-14.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.10",
                title="Security Awareness and Skills Training - Sub-Control #10",
                asset_type="Personnel",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-14.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-14.11",
                title="Security Awareness and Skills Training - Sub-Control #11",
                asset_type="Personnel",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-14.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.1",
                title="Service Provider Management - Sub-Control #1",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-15.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.2",
                title="Service Provider Management - Sub-Control #2",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-15.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.3",
                title="Service Provider Management - Sub-Control #3",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-15.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.4",
                title="Service Provider Management - Sub-Control #4",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-15.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.5",
                title="Service Provider Management - Sub-Control #5",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-15.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.6",
                title="Service Provider Management - Sub-Control #6",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-15.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.7",
                title="Service Provider Management - Sub-Control #7",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-15.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.8",
                title="Service Provider Management - Sub-Control #8",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-15.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.9",
                title="Service Provider Management - Sub-Control #9",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-15.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.10",
                title="Service Provider Management - Sub-Control #10",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-15.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-15.11",
                title="Service Provider Management - Sub-Control #11",
                asset_type="Third Parties",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-15.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.1",
                title="Application Software Security - Sub-Control #1",
                asset_type="Applications",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-16.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.2",
                title="Application Software Security - Sub-Control #2",
                asset_type="Applications",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-16.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.3",
                title="Application Software Security - Sub-Control #3",
                asset_type="Applications",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-16.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.4",
                title="Application Software Security - Sub-Control #4",
                asset_type="Applications",
                security_function="Protect",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-16.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.5",
                title="Application Software Security - Sub-Control #5",
                asset_type="Applications",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-16.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.6",
                title="Application Software Security - Sub-Control #6",
                asset_type="Applications",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-16.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.7",
                title="Application Software Security - Sub-Control #7",
                asset_type="Applications",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-16.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.8",
                title="Application Software Security - Sub-Control #8",
                asset_type="Applications",
                security_function="Protect",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-16.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.9",
                title="Application Software Security - Sub-Control #9",
                asset_type="Applications",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-16.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.10",
                title="Application Software Security - Sub-Control #10",
                asset_type="Applications",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-16.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-16.11",
                title="Application Software Security - Sub-Control #11",
                asset_type="Applications",
                security_function="Protect",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-16.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.1",
                title="Incident Response Management - Sub-Control #1",
                asset_type="Incidents",
                security_function="Respond",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-17.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.2",
                title="Incident Response Management - Sub-Control #2",
                asset_type="Incidents",
                security_function="Respond",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-17.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.3",
                title="Incident Response Management - Sub-Control #3",
                asset_type="Incidents",
                security_function="Respond",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-17.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.4",
                title="Incident Response Management - Sub-Control #4",
                asset_type="Incidents",
                security_function="Respond",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-17.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.5",
                title="Incident Response Management - Sub-Control #5",
                asset_type="Incidents",
                security_function="Respond",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-17.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.6",
                title="Incident Response Management - Sub-Control #6",
                asset_type="Incidents",
                security_function="Respond",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-17.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.7",
                title="Incident Response Management - Sub-Control #7",
                asset_type="Incidents",
                security_function="Respond",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-17.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.8",
                title="Incident Response Management - Sub-Control #8",
                asset_type="Incidents",
                security_function="Respond",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-17.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.9",
                title="Incident Response Management - Sub-Control #9",
                asset_type="Incidents",
                security_function="Respond",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-17.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.10",
                title="Incident Response Management - Sub-Control #10",
                asset_type="Incidents",
                security_function="Respond",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-17.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-17.11",
                title="Incident Response Management - Sub-Control #11",
                asset_type="Incidents",
                security_function="Respond",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-17.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.1",
                title="Penetration Testing - Sub-Control #1",
                asset_type="Defenses",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-18.1 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.2",
                title="Penetration Testing - Sub-Control #2",
                asset_type="Defenses",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-18.2 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.3",
                title="Penetration Testing - Sub-Control #3",
                asset_type="Defenses",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-18.3 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.4",
                title="Penetration Testing - Sub-Control #4",
                asset_type="Defenses",
                security_function="Identify",
                ig1=True,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-18.4 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.5",
                title="Penetration Testing - Sub-Control #5",
                asset_type="Defenses",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-18.5 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.6",
                title="Penetration Testing - Sub-Control #6",
                asset_type="Defenses",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-18.6 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.7",
                title="Penetration Testing - Sub-Control #7",
                asset_type="Defenses",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-18.7 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.8",
                title="Penetration Testing - Sub-Control #8",
                asset_type="Defenses",
                security_function="Identify",
                ig1=False,
                ig2=True,
                ig3=True,
                description="Safeguard specification CIS-18.8 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.9",
                title="Penetration Testing - Sub-Control #9",
                asset_type="Defenses",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-18.9 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.10",
                title="Penetration Testing - Sub-Control #10",
                asset_type="Defenses",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-18.10 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
        self.register(
            CisControl(
                control_id="CIS-18.11",
                title="Penetration Testing - Sub-Control #11",
                asset_type="Defenses",
                security_function="Identify",
                ig1=False,
                ig2=False,
                ig3=True,
                description="Safeguard specification CIS-18.11 for enterprise asset hardening and monitoring.",
                audit_procedure=[
                    "Scan network subnets for unmanaged hardware and software assets.",
                    "Verify baseline configuration compliance against CIS benchmarks.",
                    "Inspect centralized logging infrastructure and retention periods.",
                    "Audit multi-factor authentication enforcement on remote access.",
                    "Test incident response playbooks and escalation workflows.",
                ],
                remediation_procedure=[
                    "Implement dynamic asset discovery and network access control (NAC).",
                    "Automate configuration drift correction using infrastructure as code.",
                    "Deploy SIEM log forwarding agents with encrypted transport.",
                    "Enforce strict egress traffic filtering and DNS security inspection.",
                    "Conduct automated penetration testing drills and remediation.",
                ],
            )
        )
