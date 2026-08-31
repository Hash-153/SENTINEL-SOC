"""Payment Card Industry Data Security Standard (PCI-DSS v4.0) Compliance Validator."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class PciRequirement:
    req_id: str
    goal: str
    title: str
    description: str
    testing_procedures: List[str]
    guidance: List[str]
    automated_rule_key: str


class PciDssValidator:
    """Validates network architecture, encryption, and audit controls against PCI-DSS v4.0."""

    def __init__(self) -> None:
        self.requirements: Dict[str, PciRequirement] = {}
        self._load_requirements()

    def register(self, req: PciRequirement) -> None:
        self.requirements[req.req_id] = req

    def _load_requirements(self) -> None:
        self.register(
            PciRequirement(
                req_id="Req 1.1",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #1",
                description="Inspect firewall and router configs. Sub-clause Req 1.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.2",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #2",
                description="Inspect firewall and router configs. Sub-clause Req 1.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.3",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #3",
                description="Inspect firewall and router configs. Sub-clause Req 1.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.4",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #4",
                description="Inspect firewall and router configs. Sub-clause Req 1.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.5",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #5",
                description="Inspect firewall and router configs. Sub-clause Req 1.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.6",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #6",
                description="Inspect firewall and router configs. Sub-clause Req 1.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.7",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #7",
                description="Inspect firewall and router configs. Sub-clause Req 1.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.8",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #8",
                description="Inspect firewall and router configs. Sub-clause Req 1.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.9",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #9",
                description="Inspect firewall and router configs. Sub-clause Req 1.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.10",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #10",
                description="Inspect firewall and router configs. Sub-clause Req 1.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.11",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #11",
                description="Inspect firewall and router configs. Sub-clause Req 1.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.12",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #12",
                description="Inspect firewall and router configs. Sub-clause Req 1.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.13",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #13",
                description="Inspect firewall and router configs. Sub-clause Req 1.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 1.14",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Install and Maintain Network Security Controls - Specification #14",
                description="Inspect firewall and router configs. Sub-clause Req 1.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_1_14",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.1",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #1",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.2",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #2",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.3",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #3",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.4",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #4",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.5",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #5",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.6",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #6",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.7",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #7",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.8",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #8",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.9",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #9",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.10",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #10",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.11",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #11",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.12",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #12",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.13",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #13",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 2.14",
                goal="Goal 1: Build and Maintain a Secure Network",
                title="Apply Secure Configurations to All System Components - Specification #14",
                description="Ensure default passwords and vendor settings are removed. Sub-clause Req 2.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_2_14",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.1",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #1",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.2",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #2",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.3",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #3",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.4",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #4",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.5",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #5",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.6",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #6",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.7",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #7",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.8",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #8",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.9",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #9",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.10",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #10",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.11",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #11",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.12",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #12",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.13",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #13",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 3.14",
                goal="Goal 2: Protect Account Data",
                title="Protect Stored Account Data - Specification #14",
                description="Enforce encryption at rest using AES-256 for PAN and SAD data. Sub-clause Req 3.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_3_14",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.1",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #1",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.2",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #2",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.3",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #3",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.4",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #4",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.5",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #5",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.6",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #6",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.7",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #7",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.8",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #8",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.9",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #9",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.10",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #10",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.11",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #11",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.12",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #12",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.13",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #13",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 4.14",
                goal="Goal 2: Protect Account Data",
                title="Protect Cardholder Data with Strong Cryptography During Transmission - Specification #14",
                description="Require TLS 1.3 for all external transmissions. Sub-clause Req 4.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_4_14",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.1",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #1",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.2",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #2",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.3",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #3",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.4",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #4",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.5",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #5",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.6",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #6",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.7",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #7",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.8",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #8",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.9",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #9",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.10",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #10",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.11",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #11",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.12",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #12",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.13",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #13",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 5.14",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Protect All Systems and Networks from Malicious Software - Specification #14",
                description="Deploy and continuously update anti-malware and NIDS. Sub-clause Req 5.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_5_14",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.1",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #1",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.2",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #2",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.3",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #3",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.4",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #4",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.5",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #5",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.6",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #6",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.7",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #7",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.8",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #8",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.9",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #9",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.10",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #10",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.11",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #11",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.12",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #12",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.13",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #13",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 6.14",
                goal="Goal 3: Maintain a Vulnerability Management Program",
                title="Develop and Maintain Secure Systems and Software - Specification #14",
                description="Follow secure SDLC and address OWASP Top 10 vulnerabilities. Sub-clause Req 6.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_6_14",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.1",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #1",
                description="Enforce least privilege RBAC. Sub-clause Req 7.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.2",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #2",
                description="Enforce least privilege RBAC. Sub-clause Req 7.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.3",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #3",
                description="Enforce least privilege RBAC. Sub-clause Req 7.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.4",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #4",
                description="Enforce least privilege RBAC. Sub-clause Req 7.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.5",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #5",
                description="Enforce least privilege RBAC. Sub-clause Req 7.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.6",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #6",
                description="Enforce least privilege RBAC. Sub-clause Req 7.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.7",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #7",
                description="Enforce least privilege RBAC. Sub-clause Req 7.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.8",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #8",
                description="Enforce least privilege RBAC. Sub-clause Req 7.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.9",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #9",
                description="Enforce least privilege RBAC. Sub-clause Req 7.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.10",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #10",
                description="Enforce least privilege RBAC. Sub-clause Req 7.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.11",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #11",
                description="Enforce least privilege RBAC. Sub-clause Req 7.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.12",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #12",
                description="Enforce least privilege RBAC. Sub-clause Req 7.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.13",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #13",
                description="Enforce least privilege RBAC. Sub-clause Req 7.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 7.14",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Restrict Access to System Components and Cardholder Data by Business Need to Know - Specification #14",
                description="Enforce least privilege RBAC. Sub-clause Req 7.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_7_14",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.1",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #1",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.2",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #2",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.3",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #3",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.4",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #4",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.5",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #5",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.6",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #6",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.7",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #7",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.8",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #8",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.9",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #9",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.10",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #10",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.11",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #11",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.12",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #12",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.13",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #13",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 8.14",
                goal="Goal 4: Implement Strong Access Control Measures",
                title="Identify Users and Authenticate Access to System Components - Specification #14",
                description="Enforce unique IDs and multi-factor authentication. Sub-clause Req 8.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_8_14",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.1",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #1",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.2",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #2",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.3",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #3",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.4",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #4",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.5",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #5",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.6",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #6",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.7",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #7",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.8",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #8",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.9",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #9",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.10",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #10",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.11",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #11",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.12",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #12",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.13",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #13",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 10.14",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Log and Monitor All Access to System Components and Cardholder Data - Specification #14",
                description="Maintain daily review of audit logs and file integrity monitoring. Sub-clause Req 10.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_10_14",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.1",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #1",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.2",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #2",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.3",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #3",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.4",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #4",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.5",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #5",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.6",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #6",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.7",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #7",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.8",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #8",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.9",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #9",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.10",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #10",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.11",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #11",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.12",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #12",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.13",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #13",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 11.14",
                goal="Goal 5: Regularly Monitor and Test Networks",
                title="Test Security of Systems and Networks Regularly - Specification #14",
                description="Perform quarterly external and internal vulnerability scans. Sub-clause Req 11.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_11_14",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.1",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #1",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.1 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_1",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.2",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #2",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.2 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_2",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.3",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #3",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.3 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_3",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.4",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #4",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.4 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_4",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.5",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #5",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.5 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_5",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.6",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #6",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.6 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_6",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.7",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #7",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.7 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_7",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.8",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #8",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.8 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_8",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.9",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #9",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.9 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_9",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.10",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #10",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.10 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_10",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.11",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #11",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.11 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_11",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.12",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #12",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.12 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_12",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.13",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #13",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.13 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_13",
            )
        )
        self.register(
            PciRequirement(
                req_id="Req 12.14",
                goal="Goal 6: Maintain an Information Security Policy",
                title="Support Information Security with Organizational Policies and Programs - Specification #14",
                description="Conduct periodic risk assessments and staff awareness training. Sub-clause Req 12.14 mandating strict validation procedures.",
                testing_procedures=[
                    "Examine firewall and router configuration rules.",
                    "Verify encryption algorithms adhere to NIST standards.",
                    "Inspect system logs for unauthorized cardholder data access.",
                    "Audit penetration test reports and remediation timelines.",
                    "Confirm physical access controls and visitor logs.",
                ],
                guidance=[
                    "Prohibit direct public internet access into cardholder data environments.",
                    "Deploy network segmentation and micro-segmentation firewalls.",
                    "Enforce centralized key management and periodic key rotation.",
                    "Implement multi-factor authentication for all administrative sessions.",
                    "Retain audit logs for at least one year with 90 days immediately available.",
                ],
                automated_rule_key="pci_rule_req_12_14",
            )
        )
