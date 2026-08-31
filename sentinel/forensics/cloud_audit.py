"""AWS CloudTrail, GCP Cloud Audit, and Azure Activity Log Security Dissector."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import json


@dataclass
class CloudSecurityEvent:
    cloud_provider: str  # AWS, GCP, AZURE
    event_id: str
    event_time: str
    event_name: str
    event_source: str
    user_identity: str
    src_ip: str
    user_agent: str
    request_parameters: Dict[str, Any]
    response_elements: Dict[str, Any]
    threat_category: Optional[str] = None
    severity: str = "LOW"


class CloudAuditAnalyzer:
    """Dissects and audits Cloud Control Plane API events for credential compromise and infrastructure tampering."""

    def __init__(self) -> None:
        self.rules: List[Dict[str, Any]] = []
        self._load_cloud_rules()

    def parse_aws_event(self, record_json: str) -> Optional[CloudSecurityEvent]:
        try:
            data = json.loads(record_json) if isinstance(record_json, str) else record_json
            event = CloudSecurityEvent(
                cloud_provider="AWS",
                event_id=data.get("eventID", ""),
                event_time=data.get("eventTime", ""),
                event_name=data.get("eventName", ""),
                event_source=data.get("eventSource", ""),
                user_identity=data.get("userIdentity", {}).get("arn", "unknown"),
                src_ip=data.get("sourceIPAddress", ""),
                user_agent=data.get("userAgent", ""),
                request_parameters=data.get("requestParameters", {}) or {},
                response_elements=data.get("responseElements", {}) or {},
            )
            self._evaluate_cloud_rules(event)
            return event
        except Exception:
            return None

    def _evaluate_cloud_rules(self, event: CloudSecurityEvent) -> None:
        for rule in self.rules:
            if event.event_name.lower() == rule["event_name"].lower():
                event.threat_category = rule["category"]
                event.severity = rule["severity"]
                break

    def _load_cloud_rules(self) -> None:
        self.rules.append({
            "rule_id": "CLOUD-SIG-0001",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #1",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0002",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #2",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0003",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #3",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0004",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #4",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0005",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #5",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0006",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #6",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0007",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #7",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0008",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #8",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0009",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #9",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0010",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #10",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0011",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #11",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0012",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #12",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0013",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #13",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0014",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #14",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0015",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #15",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0016",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #16",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0017",
            "event_name": "StopLogging",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Disabling CloudTrail audit trail logging. Profile #17",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0018",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #1",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0019",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #2",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0020",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #3",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0021",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #4",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0022",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #5",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0023",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #6",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0024",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #7",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0025",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #8",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0026",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #9",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0027",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #10",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0028",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #11",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0029",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #12",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0030",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #13",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0031",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #14",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0032",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #15",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0033",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #16",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0034",
            "event_name": "DeleteTrail",
            "category": "DEFENSE_EVASION",
            "severity": "CRITICAL",
            "description": "Deleting security audit trail. Profile #17",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0035",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #1",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0036",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #2",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0037",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #3",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0038",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #4",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0039",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #5",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0040",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #6",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0041",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #7",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0042",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #8",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0043",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #9",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0044",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #10",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0045",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #11",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0046",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #12",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0047",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #13",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0048",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #14",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0049",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #15",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0050",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #16",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0051",
            "event_name": "AuthorizeSecurityGroupIngress",
            "category": "DEFENSE_EVASION",
            "severity": "HIGH",
            "description": "Opening 0.0.0.0/0 inbound security group rules. Profile #17",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0052",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #1",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0053",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #2",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0054",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #3",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0055",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #4",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0056",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #5",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0057",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #6",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0058",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #7",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0059",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #8",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0060",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #9",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0061",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #10",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0062",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #11",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0063",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #12",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0064",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #13",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0065",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #14",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0066",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #15",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0067",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #16",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0068",
            "event_name": "PutBucketPolicy",
            "category": "DATA_EXFILTRATION",
            "severity": "HIGH",
            "description": "Making S3 storage buckets publicly readable. Profile #17",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0069",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #1",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0070",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #2",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0071",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #3",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0072",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #4",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0073",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #5",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0074",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #6",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0075",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #7",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0076",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #8",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0077",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #9",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0078",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #10",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0079",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #11",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0080",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #12",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0081",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #13",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0082",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #14",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0083",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #15",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0084",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #16",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0085",
            "event_name": "CreateAccessKey",
            "category": "CREDENTIAL_ACCESS",
            "severity": "HIGH",
            "description": "Generating permanent IAM API access keys. Profile #17",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0086",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #1",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0087",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #2",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0088",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #3",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0089",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #4",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0090",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #5",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0091",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #6",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0092",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #7",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0093",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #8",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0094",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #9",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0095",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #10",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0096",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #11",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0097",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #12",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0098",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #13",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0099",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #14",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0100",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #15",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0101",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #16",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0102",
            "event_name": "CreateUser",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": "Creating new unmanaged IAM user accounts. Profile #17",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0103",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #1",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0104",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #2",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0105",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #3",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0106",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #4",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0107",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #5",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0108",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #6",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0109",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #7",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0110",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #8",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0111",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #9",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0112",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #10",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0113",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #11",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0114",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #12",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0115",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #13",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0116",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #14",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0117",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #15",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0118",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #16",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0119",
            "event_name": "AttachUserPolicy",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Attaching AdministratorAccess policy to identity. Profile #17",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0120",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #1",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0121",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #2",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0122",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #3",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0123",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #4",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0124",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #5",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0125",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #6",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0126",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #7",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0127",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #8",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0128",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #9",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0129",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #10",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0130",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #11",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0131",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #12",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0132",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #13",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0133",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #14",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0134",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #15",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0135",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #16",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0136",
            "event_name": "ConsoleLogin",
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "description": "Console login without multi-factor authentication. Profile #17",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0137",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #1",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0138",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #2",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0139",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #3",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0140",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #4",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0141",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #5",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0142",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #6",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0143",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #7",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0144",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #8",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0145",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #9",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0146",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #10",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0147",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #11",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0148",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #12",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0149",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #13",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0150",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #14",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0151",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #15",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0152",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #16",
        })
        self.rules.append({
            "rule_id": "CLOUD-SIG-0153",
            "event_name": "ModifyVpcEndpointServiceConfiguration",
            "category": "PERSISTENCE",
            "severity": "HIGH",
            "description": "Exposing internal VPC endpoint services. Profile #17",
        })
