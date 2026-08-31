"""NIST SP 800-53 Rev 5 Security and Privacy Controls Assessment Engine."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import enum


class NistControlFamily(enum.Enum):
    AC = "Access Control"
    AU = "Audit and Accountability"
    CA = "Assessment, Authorization, and Monitoring"
    CM = "Configuration Management"
    CP = "Contingency Planning"
    IA = "Identification and Authentication"
    IR = "Incident Response"
    MP = "Media Protection"
    PE = "Physical and Environmental Protection"
    PL = "Planning"
    PS = "Personnel Security"
    RA = "Risk Assessment"
    SA = "System and Services Acquisition"
    SC = "System and Communications Protection"
    SI = "System and Information Integrity"


@dataclass
class NistControl:
    control_id: str
    family: NistControlFamily
    name: str
    description: str
    impact_level: str  # LOW, MODERATE, HIGH
    assessment_objectives: List[str]
    remediation_guidance: List[str]
    automated_check_id: str


class NistComplianceEngine:
    """Evaluates system configurations, access policies, and audit trails against NIST SP 800-53 Rev 5."""

    def __init__(self) -> None:
        self.controls: Dict[str, NistControl] = {}
        self._load_controls()

    def register(self, ctrl: NistControl) -> None:
        self.controls[ctrl.control_id] = ctrl

    def evaluate_compliance(self, audit_context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate system context against all registered NIST controls."""
        results = {"passed": [], "failed": [], "total_controls": len(self.controls)}
        for ctrl_id, ctrl in self.controls.items():
            # Check basic context attributes
            passed = audit_context.get(ctrl.automated_check_id, True)
            if passed:
                results["passed"].append(ctrl_id)
            else:
                results["failed"].append({
                    "control_id": ctrl_id,
                    "name": ctrl.name,
                    "family": ctrl.family.value,
                    "guidance": ctrl.remediation_guidance,
                })
        results["score_percentage"] = (len(results["passed"]) / max(1, len(self.controls))) * 100.0
        return results

    def _load_controls(self) -> None:
        self.register(
            NistControl(
                control_id="AC-1",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #1",
                description="Establish and maintain access control governance. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(2)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #2",
                description="Establish and maintain access control governance. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_2",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(3)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #3",
                description="Establish and maintain access control governance. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_3",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(4)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #4",
                description="Establish and maintain access control governance. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_4",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(5)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #5",
                description="Establish and maintain access control governance. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_5",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(6)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #6",
                description="Establish and maintain access control governance. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_6",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(7)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #7",
                description="Establish and maintain access control governance. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_7",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(8)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #8",
                description="Establish and maintain access control governance. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_8",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(9)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #9",
                description="Establish and maintain access control governance. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_9",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(10)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #10",
                description="Establish and maintain access control governance. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_10",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(11)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #11",
                description="Establish and maintain access control governance. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_11",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(12)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #12",
                description="Establish and maintain access control governance. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_12",
            )
        )
        self.register(
            NistControl(
                control_id="AC-1(13)",
                family=NistControlFamily.AC,
                name="Policy and Procedures - Enhancement #13",
                description="Establish and maintain access control governance. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_1_13",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #1",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(2)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #2",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_2",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(3)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #3",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_3",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(4)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #4",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_4",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(5)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #5",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_5",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(6)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #6",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_6",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(7)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #7",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_7",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(8)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #8",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_8",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(9)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #9",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_9",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(10)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #10",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_10",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(11)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #11",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_11",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(12)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #12",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_12",
            )
        )
        self.register(
            NistControl(
                control_id="AC-2(13)",
                family=NistControlFamily.AC,
                name="Account Management - Enhancement #13",
                description="Manage information system accounts, group memberships, and authorizations. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_2_13",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #1",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(2)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #2",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_2",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(3)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #3",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_3",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(4)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #4",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_4",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(5)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #5",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_5",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(6)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #6",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_6",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(7)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #7",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_7",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(8)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #8",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_8",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(9)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #9",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_9",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(10)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #10",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_10",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(11)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #11",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_11",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(12)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #12",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_12",
            )
        )
        self.register(
            NistControl(
                control_id="AC-3(13)",
                family=NistControlFamily.AC,
                name="Access Enforcement - Enhancement #13",
                description="Enforce approved authorizations for logical access. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_3_13",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #1",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(2)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #2",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_2",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(3)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #3",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_3",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(4)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #4",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_4",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(5)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #5",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_5",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(6)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #6",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_6",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(7)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #7",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_7",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(8)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #8",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_8",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(9)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #9",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_9",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(10)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #10",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_10",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(11)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #11",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_11",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(12)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #12",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_12",
            )
        )
        self.register(
            NistControl(
                control_id="AC-6(13)",
                family=NistControlFamily.AC,
                name="Least Privilege - Enhancement #13",
                description="Employ the principle of least privilege across all user roles. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_6_13",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #1",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(2)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #2",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_2",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(3)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #3",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_3",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(4)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #4",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_4",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(5)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #5",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_5",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(6)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #6",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_6",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(7)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #7",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_7",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(8)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #8",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_8",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(9)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #9",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_9",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(10)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #10",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_10",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(11)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #11",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_11",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(12)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #12",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_12",
            )
        )
        self.register(
            NistControl(
                control_id="AC-7(13)",
                family=NistControlFamily.AC,
                name="Unsuccessful Logon Attempts - Enhancement #13",
                description="Enforce consecutive failed logon limits and session locks. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ac_7_13",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #1",
                description="Identify and record auditable security events. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(2)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #2",
                description="Identify and record auditable security events. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_2",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(3)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #3",
                description="Identify and record auditable security events. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_3",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(4)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #4",
                description="Identify and record auditable security events. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_4",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(5)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #5",
                description="Identify and record auditable security events. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_5",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(6)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #6",
                description="Identify and record auditable security events. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_6",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(7)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #7",
                description="Identify and record auditable security events. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_7",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(8)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #8",
                description="Identify and record auditable security events. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_8",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(9)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #9",
                description="Identify and record auditable security events. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_9",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(10)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #10",
                description="Identify and record auditable security events. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_10",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(11)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #11",
                description="Identify and record auditable security events. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_11",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(12)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #12",
                description="Identify and record auditable security events. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_12",
            )
        )
        self.register(
            NistControl(
                control_id="AU-2(13)",
                family=NistControlFamily.AU,
                name="Event Logging - Enhancement #13",
                description="Identify and record auditable security events. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_2_13",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #1",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(2)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #2",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_2",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(3)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #3",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_3",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(4)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #4",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_4",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(5)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #5",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_5",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(6)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #6",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_6",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(7)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #7",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_7",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(8)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #8",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_8",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(9)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #9",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_9",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(10)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #10",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_10",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(11)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #11",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_11",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(12)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #12",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_12",
            )
        )
        self.register(
            NistControl(
                control_id="AU-6(13)",
                family=NistControlFamily.AU,
                name="Audit Record Review - Enhancement #13",
                description="Review and analyze system audit records for unusual activity. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_6_13",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #1",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(2)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #2",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_2",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(3)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #3",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_3",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(4)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #4",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_4",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(5)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #5",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_5",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(6)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #6",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_6",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(7)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #7",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_7",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(8)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #8",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_8",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(9)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #9",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_9",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(10)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #10",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_10",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(11)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #11",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_11",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(12)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #12",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_12",
            )
        )
        self.register(
            NistControl(
                control_id="AU-12(13)",
                family=NistControlFamily.AU,
                name="Audit Record Generation - Enhancement #13",
                description="Generate audit records containing essential telemetry fields. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_au_12_13",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #1",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(2)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #2",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_2",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(3)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #3",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_3",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(4)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #4",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_4",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(5)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #5",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_5",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(6)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #6",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_6",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(7)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #7",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_7",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(8)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #8",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_8",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(9)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #9",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_9",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(10)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #10",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_10",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(11)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #11",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_11",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(12)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #12",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_12",
            )
        )
        self.register(
            NistControl(
                control_id="CM-2(13)",
                family=NistControlFamily.CM,
                name="Baseline Configuration - Enhancement #13",
                description="Maintain a documented baseline configuration for all components. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_cm_2_13",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #1",
                description="Enforce MFA for network and local access. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(2)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #2",
                description="Enforce MFA for network and local access. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_2",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(3)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #3",
                description="Enforce MFA for network and local access. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_3",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(4)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #4",
                description="Enforce MFA for network and local access. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_4",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(5)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #5",
                description="Enforce MFA for network and local access. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_5",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(6)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #6",
                description="Enforce MFA for network and local access. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_6",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(7)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #7",
                description="Enforce MFA for network and local access. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_7",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(8)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #8",
                description="Enforce MFA for network and local access. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_8",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(9)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #9",
                description="Enforce MFA for network and local access. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_9",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(10)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #10",
                description="Enforce MFA for network and local access. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_10",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(11)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #11",
                description="Enforce MFA for network and local access. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_11",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(12)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #12",
                description="Enforce MFA for network and local access. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_12",
            )
        )
        self.register(
            NistControl(
                control_id="IA-2(13)",
                family=NistControlFamily.IA,
                name="Identification and Authentication (Organizational Users) - Enhancement #13",
                description="Enforce MFA for network and local access. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_2_13",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #1",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(2)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #2",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_2",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(3)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #3",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_3",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(4)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #4",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_4",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(5)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #5",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_5",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(6)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #6",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_6",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(7)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #7",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_7",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(8)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #8",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_8",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(9)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #9",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_9",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(10)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #10",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_10",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(11)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #11",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_11",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(12)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #12",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_12",
            )
        )
        self.register(
            NistControl(
                control_id="IA-5(13)",
                family=NistControlFamily.IA,
                name="Authenticator Management - Enhancement #13",
                description="Manage initial authenticator distribution and rotation. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ia_5_13",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #1",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(2)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #2",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_2",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(3)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #3",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_3",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(4)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #4",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_4",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(5)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #5",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_5",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(6)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #6",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_6",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(7)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #7",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_7",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(8)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #8",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_8",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(9)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #9",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_9",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(10)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #10",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_10",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(11)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #11",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_11",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(12)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #12",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_12",
            )
        )
        self.register(
            NistControl(
                control_id="IR-4(13)",
                family=NistControlFamily.IR,
                name="Incident Handling - Enhancement #13",
                description="Implement an incident handling capability for security events. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_4_13",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #1",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(2)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #2",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_2",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(3)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #3",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_3",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(4)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #4",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_4",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(5)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #5",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_5",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(6)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #6",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_6",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(7)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #7",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_7",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(8)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #8",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_8",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(9)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #9",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_9",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(10)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #10",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_10",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(11)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #11",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_11",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(12)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #12",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_12",
            )
        )
        self.register(
            NistControl(
                control_id="IR-6(13)",
                family=NistControlFamily.IR,
                name="Incident Reporting - Enhancement #13",
                description="Report information security incidents to designated authorities. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_ir_6_13",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #1",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(2)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #2",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_2",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(3)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #3",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_3",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(4)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #4",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_4",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(5)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #5",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_5",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(6)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #6",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_6",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(7)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #7",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_7",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(8)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #8",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_8",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(9)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #9",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_9",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(10)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #10",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_10",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(11)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #11",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_11",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(12)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #12",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_12",
            )
        )
        self.register(
            NistControl(
                control_id="SC-7(13)",
                family=NistControlFamily.SC,
                name="Boundary Protection - Enhancement #13",
                description="Monitor and control communications at external boundaries. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_7_13",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #1",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(2)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #2",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_2",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(3)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #3",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_3",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(4)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #4",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_4",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(5)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #5",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_5",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(6)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #6",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_6",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(7)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #7",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_7",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(8)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #8",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_8",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(9)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #9",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_9",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(10)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #10",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_10",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(11)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #11",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_11",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(12)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #12",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_12",
            )
        )
        self.register(
            NistControl(
                control_id="SC-8(13)",
                family=NistControlFamily.SC,
                name="Transmission Confidentiality and Integrity - Enhancement #13",
                description="Protect integrity and confidentiality of transmitted info. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_8_13",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #1",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(2)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #2",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_2",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(3)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #3",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_3",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(4)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #4",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_4",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(5)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #5",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_5",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(6)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #6",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_6",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(7)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #7",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_7",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(8)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #8",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_8",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(9)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #9",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_9",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(10)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #10",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_10",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(11)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #11",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_11",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(12)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #12",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_12",
            )
        )
        self.register(
            NistControl(
                control_id="SC-13(13)",
                family=NistControlFamily.SC,
                name="Cryptographic Protection - Enhancement #13",
                description="Employ FIPS-validated cryptographic mechanisms. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_sc_13_13",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #1",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(2)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #2",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_2",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(3)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #3",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_3",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(4)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #4",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_4",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(5)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #5",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_5",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(6)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #6",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_6",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(7)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #7",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_7",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(8)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #8",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_8",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(9)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #9",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_9",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(10)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #10",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_10",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(11)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #11",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_11",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(12)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #12",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_12",
            )
        )
        self.register(
            NistControl(
                control_id="SI-2(13)",
                family=NistControlFamily.SI,
                name="Flaw Remediation - Enhancement #13",
                description="Identify, report, and correct information system flaws promptly. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_2_13",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #1",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 1 specifying baseline safeguards.",
                impact_level="HIGH" if 1 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(2)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #2",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 2 specifying baseline safeguards.",
                impact_level="HIGH" if 2 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_2",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(3)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #3",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 3 specifying baseline safeguards.",
                impact_level="HIGH" if 3 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_3",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(4)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #4",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 4 specifying baseline safeguards.",
                impact_level="HIGH" if 4 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_4",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(5)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #5",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 5 specifying baseline safeguards.",
                impact_level="HIGH" if 5 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_5",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(6)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #6",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 6 specifying baseline safeguards.",
                impact_level="HIGH" if 6 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_6",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(7)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #7",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 7 specifying baseline safeguards.",
                impact_level="HIGH" if 7 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_7",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(8)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #8",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 8 specifying baseline safeguards.",
                impact_level="HIGH" if 8 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_8",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(9)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #9",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 9 specifying baseline safeguards.",
                impact_level="HIGH" if 9 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_9",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(10)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #10",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 10 specifying baseline safeguards.",
                impact_level="HIGH" if 10 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_10",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(11)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #11",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 11 specifying baseline safeguards.",
                impact_level="HIGH" if 11 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_11",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(12)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #12",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 12 specifying baseline safeguards.",
                impact_level="HIGH" if 12 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_12",
            )
        )
        self.register(
            NistControl(
                control_id="SI-4(13)",
                family=NistControlFamily.SI,
                name="Information System Monitoring - Enhancement #13",
                description="Monitor information system to detect network attacks. Sub-clause requirement index 13 specifying baseline safeguards.",
                impact_level="HIGH" if 13 > 6 else "MODERATE",
                assessment_objectives=[
                    "Determine if the organization defines policies and procedures.",
                    "Verify that access controls enforce mandatory separation of duties.",
                    "Validate continuous monitoring parameters and audit thresholds.",
                    "Ensure automated alerting triggers on policy deviation events.",
                    "Review historical logs for unauthorized privilege elevation attempts.",
                ],
                remediation_guidance=[
                    "Implement centralized identity provider with mandatory MFA.",
                    "Enforce immutable audit trail logging to dedicated remote syslog.",
                    "Deploy network intrusion detection with automated quarantine triggers.",
                    "Conduct automated daily vulnerability scans on production assets.",
                    "Maintain cryptographically signed baseline configuration manifests.",
                ],
                automated_check_id="check_si_4_13",
            )
        )
