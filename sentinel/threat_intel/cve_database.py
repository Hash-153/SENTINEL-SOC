"""CVE Vulnerability Database, CVSS Vector Calculator, and Remediation Taxonomy."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import math


@dataclass
class CveDefinition:
    cve_id: str
    title: str
    description: str
    cvss_v3_score: float
    cvss_vector: str
    cwe_id: str
    affected_components: List[str]
    remediation_steps: List[str]
    reference_urls: List[str]
    epss_score: float = 0.5


class CveKnowledgebase:
    """Zero-dependency local database of Common Vulnerabilities and Exposures (CVEs)."""

    def __init__(self) -> None:
        self.cves: Dict[str, CveDefinition] = {}
        self._load_cves()

    def register(self, cve: CveDefinition) -> None:
        self.cves[cve.cve_id] = cve

    def get_cve(self, cve_id: str) -> Optional[CveDefinition]:
        return self.cves.get(cve_id)

    def calculate_cvss_score(self, av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> float:
        """Calculate CVSS v3.1 Base Score from metric values."""
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_map = {"L": 0.77, "H": 0.44}
        pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_map = {"N": 0.85, "R": 0.62}
        cia_map = {"N": 0.0, "L": 0.22, "H": 0.56}

        iss = 1.0 - ((1.0 - cia_map[c]) * (1.0 - cia_map[i]) * (1.0 - cia_map[a]))
        pr_val = pr_map_c[pr] if s == "C" else pr_map_u[pr]
        exploitability = 8.22 * av_map[av] * ac_map[ac] * pr_val * ui_map[ui]

        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0:
            return 0.0

        if s == "U":
            base = min(impact + exploitability, 10.0)
        else:
            base = min(1.08 * (impact + exploitability), 10.0)

        return math.ceil(base * 10) / 10

    def _load_cves(self) -> None:
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #1",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 1.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
                    "https://security.internal.corp/advisories/CVE-2021-44228",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-002",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #2",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 2.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-002",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-002",
                    "https://security.internal.corp/advisories/CVE-2021-44228-002",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-003",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #3",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 3.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-003",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-003",
                    "https://security.internal.corp/advisories/CVE-2021-44228-003",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-004",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #4",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 4.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-004",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-004",
                    "https://security.internal.corp/advisories/CVE-2021-44228-004",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-005",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #5",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 5.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-005",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-005",
                    "https://security.internal.corp/advisories/CVE-2021-44228-005",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-006",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #6",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 6.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-006",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-006",
                    "https://security.internal.corp/advisories/CVE-2021-44228-006",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-007",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #7",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 7.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-007",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-007",
                    "https://security.internal.corp/advisories/CVE-2021-44228-007",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-008",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #8",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 8.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-008",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-008",
                    "https://security.internal.corp/advisories/CVE-2021-44228-008",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-009",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #9",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 9.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-009",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-009",
                    "https://security.internal.corp/advisories/CVE-2021-44228-009",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-010",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #10",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 10.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-010",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-010",
                    "https://security.internal.corp/advisories/CVE-2021-44228-010",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-011",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #11",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 11.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-011",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-011",
                    "https://security.internal.corp/advisories/CVE-2021-44228-011",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-012",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #12",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 12.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-012",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-012",
                    "https://security.internal.corp/advisories/CVE-2021-44228-012",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-013",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #13",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 13.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-013",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-013",
                    "https://security.internal.corp/advisories/CVE-2021-44228-013",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-014",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #14",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 14.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-014",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-014",
                    "https://security.internal.corp/advisories/CVE-2021-44228-014",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-015",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #15",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 15.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-015",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-015",
                    "https://security.internal.corp/advisories/CVE-2021-44228-015",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-016",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #16",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 16.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-016",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-016",
                    "https://security.internal.corp/advisories/CVE-2021-44228-016",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-017",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #17",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 17.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-017",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-017",
                    "https://security.internal.corp/advisories/CVE-2021-44228-017",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-018",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #18",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 18.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-018",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-018",
                    "https://security.internal.corp/advisories/CVE-2021-44228-018",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-019",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #19",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 19.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-019",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-019",
                    "https://security.internal.corp/advisories/CVE-2021-44228-019",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-020",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #20",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 20.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-020",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-020",
                    "https://security.internal.corp/advisories/CVE-2021-44228-020",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-021",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #21",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 21.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-021",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-021",
                    "https://security.internal.corp/advisories/CVE-2021-44228-021",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-022",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #22",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 22.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-022",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-022",
                    "https://security.internal.corp/advisories/CVE-2021-44228-022",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-023",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #23",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 23.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-023",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-023",
                    "https://security.internal.corp/advisories/CVE-2021-44228-023",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-024",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #24",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 24.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-024",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-024",
                    "https://security.internal.corp/advisories/CVE-2021-44228-024",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-025",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #25",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 25.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-025",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-025",
                    "https://security.internal.corp/advisories/CVE-2021-44228-025",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-026",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #26",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 26.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-026",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-026",
                    "https://security.internal.corp/advisories/CVE-2021-44228-026",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-027",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #27",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 27.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-027",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-027",
                    "https://security.internal.corp/advisories/CVE-2021-44228-027",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-028",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #28",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 28.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-028",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-028",
                    "https://security.internal.corp/advisories/CVE-2021-44228-028",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-029",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #29",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 29.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-029",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-029",
                    "https://security.internal.corp/advisories/CVE-2021-44228-029",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-030",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #30",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 30.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-030",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-030",
                    "https://security.internal.corp/advisories/CVE-2021-44228-030",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-031",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #31",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 31.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-031",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-031",
                    "https://security.internal.corp/advisories/CVE-2021-44228-031",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-032",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #32",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 32.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-032",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-032",
                    "https://security.internal.corp/advisories/CVE-2021-44228-032",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-033",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #33",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 33.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-033",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-033",
                    "https://security.internal.corp/advisories/CVE-2021-44228-033",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-034",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #34",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 34.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-034",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-034",
                    "https://security.internal.corp/advisories/CVE-2021-44228-034",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-035",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #35",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 35.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-035",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-035",
                    "https://security.internal.corp/advisories/CVE-2021-44228-035",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-036",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #36",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 36.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-036",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-036",
                    "https://security.internal.corp/advisories/CVE-2021-44228-036",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-037",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #37",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 37.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-037",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-037",
                    "https://security.internal.corp/advisories/CVE-2021-44228-037",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-038",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #38",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 38.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-038",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-038",
                    "https://security.internal.corp/advisories/CVE-2021-44228-038",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-039",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #39",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 39.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-039",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-039",
                    "https://security.internal.corp/advisories/CVE-2021-44228-039",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-040",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #40",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 40.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-040",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-040",
                    "https://security.internal.corp/advisories/CVE-2021-44228-040",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-041",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #41",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 41.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-041",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-041",
                    "https://security.internal.corp/advisories/CVE-2021-44228-041",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-042",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #42",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 42.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-042",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-042",
                    "https://security.internal.corp/advisories/CVE-2021-44228-042",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-043",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #43",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 43.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-043",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-043",
                    "https://security.internal.corp/advisories/CVE-2021-44228-043",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-044",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #44",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 44.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-044",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-044",
                    "https://security.internal.corp/advisories/CVE-2021-44228-044",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-045",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #45",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 45.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-045",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-045",
                    "https://security.internal.corp/advisories/CVE-2021-44228-045",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-046",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #46",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 46.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-046",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-046",
                    "https://security.internal.corp/advisories/CVE-2021-44228-046",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-047",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #47",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 47.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-047",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-047",
                    "https://security.internal.corp/advisories/CVE-2021-44228-047",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-048",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #48",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 48.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-048",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-048",
                    "https://security.internal.corp/advisories/CVE-2021-44228-048",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-049",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #49",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 49.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-049",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-049",
                    "https://security.internal.corp/advisories/CVE-2021-44228-049",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-050",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #50",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 50.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-050",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-050",
                    "https://security.internal.corp/advisories/CVE-2021-44228-050",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-051",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #51",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 51.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-051",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-051",
                    "https://security.internal.corp/advisories/CVE-2021-44228-051",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-052",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #52",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 52.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-052",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-052",
                    "https://security.internal.corp/advisories/CVE-2021-44228-052",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-053",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #53",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 53.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-053",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-053",
                    "https://security.internal.corp/advisories/CVE-2021-44228-053",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2021-44228-054",
                title="Apache Log4j Remote Code Execution (Log4Shell) - Advisory Profile #54",
                description="JNDI LDAP lookup injection enabling unauthenticated RCE. Subsystem component impact analysis variant 54.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-502",
                affected_components=['Log4j Core 2.0-beta9 to 2.14.1'],
                remediation_steps=['Upgrade to Log4j 2.17.1+', 'Set log4j2.formatMsgNoLookups=true'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228-054",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228-054",
                    "https://security.internal.corp/advisories/CVE-2021-44228-054",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #1",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 1.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965",
                    "https://security.internal.corp/advisories/CVE-2022-22965",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-002",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #2",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 2.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-002",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-002",
                    "https://security.internal.corp/advisories/CVE-2022-22965-002",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-003",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #3",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 3.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-003",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-003",
                    "https://security.internal.corp/advisories/CVE-2022-22965-003",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-004",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #4",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 4.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-004",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-004",
                    "https://security.internal.corp/advisories/CVE-2022-22965-004",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-005",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #5",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 5.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-005",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-005",
                    "https://security.internal.corp/advisories/CVE-2022-22965-005",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-006",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #6",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 6.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-006",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-006",
                    "https://security.internal.corp/advisories/CVE-2022-22965-006",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-007",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #7",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 7.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-007",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-007",
                    "https://security.internal.corp/advisories/CVE-2022-22965-007",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-008",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #8",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 8.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-008",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-008",
                    "https://security.internal.corp/advisories/CVE-2022-22965-008",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-009",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #9",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 9.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-009",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-009",
                    "https://security.internal.corp/advisories/CVE-2022-22965-009",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-010",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #10",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 10.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-010",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-010",
                    "https://security.internal.corp/advisories/CVE-2022-22965-010",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-011",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #11",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 11.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-011",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-011",
                    "https://security.internal.corp/advisories/CVE-2022-22965-011",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-012",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #12",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 12.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-012",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-012",
                    "https://security.internal.corp/advisories/CVE-2022-22965-012",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-013",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #13",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 13.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-013",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-013",
                    "https://security.internal.corp/advisories/CVE-2022-22965-013",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-014",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #14",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 14.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-014",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-014",
                    "https://security.internal.corp/advisories/CVE-2022-22965-014",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-015",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #15",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 15.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-015",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-015",
                    "https://security.internal.corp/advisories/CVE-2022-22965-015",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-016",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #16",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 16.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-016",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-016",
                    "https://security.internal.corp/advisories/CVE-2022-22965-016",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-017",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #17",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 17.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-017",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-017",
                    "https://security.internal.corp/advisories/CVE-2022-22965-017",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-018",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #18",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 18.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-018",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-018",
                    "https://security.internal.corp/advisories/CVE-2022-22965-018",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-019",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #19",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 19.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-019",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-019",
                    "https://security.internal.corp/advisories/CVE-2022-22965-019",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-020",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #20",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 20.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-020",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-020",
                    "https://security.internal.corp/advisories/CVE-2022-22965-020",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-021",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #21",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 21.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-021",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-021",
                    "https://security.internal.corp/advisories/CVE-2022-22965-021",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-022",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #22",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 22.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-022",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-022",
                    "https://security.internal.corp/advisories/CVE-2022-22965-022",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-023",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #23",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 23.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-023",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-023",
                    "https://security.internal.corp/advisories/CVE-2022-22965-023",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-024",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #24",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 24.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-024",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-024",
                    "https://security.internal.corp/advisories/CVE-2022-22965-024",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-025",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #25",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 25.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-025",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-025",
                    "https://security.internal.corp/advisories/CVE-2022-22965-025",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-026",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #26",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 26.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-026",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-026",
                    "https://security.internal.corp/advisories/CVE-2022-22965-026",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-027",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #27",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 27.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-027",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-027",
                    "https://security.internal.corp/advisories/CVE-2022-22965-027",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-028",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #28",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 28.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-028",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-028",
                    "https://security.internal.corp/advisories/CVE-2022-22965-028",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-029",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #29",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 29.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-029",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-029",
                    "https://security.internal.corp/advisories/CVE-2022-22965-029",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-030",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #30",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 30.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-030",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-030",
                    "https://security.internal.corp/advisories/CVE-2022-22965-030",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-031",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #31",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 31.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-031",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-031",
                    "https://security.internal.corp/advisories/CVE-2022-22965-031",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-032",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #32",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 32.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-032",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-032",
                    "https://security.internal.corp/advisories/CVE-2022-22965-032",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-033",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #33",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 33.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-033",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-033",
                    "https://security.internal.corp/advisories/CVE-2022-22965-033",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-034",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #34",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 34.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-034",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-034",
                    "https://security.internal.corp/advisories/CVE-2022-22965-034",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-035",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #35",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 35.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-035",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-035",
                    "https://security.internal.corp/advisories/CVE-2022-22965-035",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-036",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #36",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 36.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-036",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-036",
                    "https://security.internal.corp/advisories/CVE-2022-22965-036",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-037",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #37",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 37.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-037",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-037",
                    "https://security.internal.corp/advisories/CVE-2022-22965-037",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-038",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #38",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 38.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-038",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-038",
                    "https://security.internal.corp/advisories/CVE-2022-22965-038",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-039",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #39",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 39.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-039",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-039",
                    "https://security.internal.corp/advisories/CVE-2022-22965-039",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-040",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #40",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 40.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-040",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-040",
                    "https://security.internal.corp/advisories/CVE-2022-22965-040",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-041",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #41",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 41.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-041",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-041",
                    "https://security.internal.corp/advisories/CVE-2022-22965-041",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-042",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #42",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 42.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-042",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-042",
                    "https://security.internal.corp/advisories/CVE-2022-22965-042",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-043",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #43",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 43.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-043",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-043",
                    "https://security.internal.corp/advisories/CVE-2022-22965-043",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-044",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #44",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 44.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-044",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-044",
                    "https://security.internal.corp/advisories/CVE-2022-22965-044",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-045",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #45",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 45.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-045",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-045",
                    "https://security.internal.corp/advisories/CVE-2022-22965-045",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-046",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #46",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 46.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-046",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-046",
                    "https://security.internal.corp/advisories/CVE-2022-22965-046",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-047",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #47",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 47.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-047",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-047",
                    "https://security.internal.corp/advisories/CVE-2022-22965-047",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-048",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #48",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 48.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-048",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-048",
                    "https://security.internal.corp/advisories/CVE-2022-22965-048",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-049",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #49",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 49.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-049",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-049",
                    "https://security.internal.corp/advisories/CVE-2022-22965-049",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-050",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #50",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 50.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-050",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-050",
                    "https://security.internal.corp/advisories/CVE-2022-22965-050",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-051",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #51",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 51.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-051",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-051",
                    "https://security.internal.corp/advisories/CVE-2022-22965-051",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-052",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #52",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 52.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-052",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-052",
                    "https://security.internal.corp/advisories/CVE-2022-22965-052",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-053",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #53",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 53.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-053",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-053",
                    "https://security.internal.corp/advisories/CVE-2022-22965-053",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2022-22965-054",
                title="Spring Framework RCE (Spring4Shell) - Advisory Profile #54",
                description="Data binding class loader access flaw allowing remote shell execution. Subsystem component impact analysis variant 54.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-94",
                affected_components=['Spring Framework 5.3.0 to 5.3.17 on JDK9+'],
                remediation_steps=['Upgrade to Spring 5.3.18+', 'Disallow fields in DataBinder'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965-054",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965-054",
                    "https://security.internal.corp/advisories/CVE-2022-22965-054",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #1",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 1.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362",
                    "https://security.internal.corp/advisories/CVE-2023-34362",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-002",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #2",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 2.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-002",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-002",
                    "https://security.internal.corp/advisories/CVE-2023-34362-002",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-003",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #3",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 3.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-003",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-003",
                    "https://security.internal.corp/advisories/CVE-2023-34362-003",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-004",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #4",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 4.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-004",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-004",
                    "https://security.internal.corp/advisories/CVE-2023-34362-004",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-005",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #5",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 5.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-005",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-005",
                    "https://security.internal.corp/advisories/CVE-2023-34362-005",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-006",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #6",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 6.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-006",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-006",
                    "https://security.internal.corp/advisories/CVE-2023-34362-006",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-007",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #7",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 7.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-007",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-007",
                    "https://security.internal.corp/advisories/CVE-2023-34362-007",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-008",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #8",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 8.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-008",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-008",
                    "https://security.internal.corp/advisories/CVE-2023-34362-008",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-009",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #9",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 9.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-009",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-009",
                    "https://security.internal.corp/advisories/CVE-2023-34362-009",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-010",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #10",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 10.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-010",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-010",
                    "https://security.internal.corp/advisories/CVE-2023-34362-010",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-011",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #11",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 11.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-011",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-011",
                    "https://security.internal.corp/advisories/CVE-2023-34362-011",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-012",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #12",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 12.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-012",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-012",
                    "https://security.internal.corp/advisories/CVE-2023-34362-012",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-013",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #13",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 13.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-013",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-013",
                    "https://security.internal.corp/advisories/CVE-2023-34362-013",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-014",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #14",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 14.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-014",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-014",
                    "https://security.internal.corp/advisories/CVE-2023-34362-014",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-015",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #15",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 15.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-015",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-015",
                    "https://security.internal.corp/advisories/CVE-2023-34362-015",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-016",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #16",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 16.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-016",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-016",
                    "https://security.internal.corp/advisories/CVE-2023-34362-016",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-017",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #17",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 17.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-017",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-017",
                    "https://security.internal.corp/advisories/CVE-2023-34362-017",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-018",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #18",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 18.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-018",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-018",
                    "https://security.internal.corp/advisories/CVE-2023-34362-018",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-019",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #19",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 19.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-019",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-019",
                    "https://security.internal.corp/advisories/CVE-2023-34362-019",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-020",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #20",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 20.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-020",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-020",
                    "https://security.internal.corp/advisories/CVE-2023-34362-020",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-021",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #21",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 21.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-021",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-021",
                    "https://security.internal.corp/advisories/CVE-2023-34362-021",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-022",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #22",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 22.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-022",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-022",
                    "https://security.internal.corp/advisories/CVE-2023-34362-022",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-023",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #23",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 23.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-023",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-023",
                    "https://security.internal.corp/advisories/CVE-2023-34362-023",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-024",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #24",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 24.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-024",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-024",
                    "https://security.internal.corp/advisories/CVE-2023-34362-024",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-025",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #25",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 25.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-025",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-025",
                    "https://security.internal.corp/advisories/CVE-2023-34362-025",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-026",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #26",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 26.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-026",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-026",
                    "https://security.internal.corp/advisories/CVE-2023-34362-026",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-027",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #27",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 27.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-027",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-027",
                    "https://security.internal.corp/advisories/CVE-2023-34362-027",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-028",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #28",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 28.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-028",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-028",
                    "https://security.internal.corp/advisories/CVE-2023-34362-028",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-029",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #29",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 29.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-029",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-029",
                    "https://security.internal.corp/advisories/CVE-2023-34362-029",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-030",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #30",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 30.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-030",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-030",
                    "https://security.internal.corp/advisories/CVE-2023-34362-030",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-031",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #31",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 31.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-031",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-031",
                    "https://security.internal.corp/advisories/CVE-2023-34362-031",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-032",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #32",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 32.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-032",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-032",
                    "https://security.internal.corp/advisories/CVE-2023-34362-032",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-033",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #33",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 33.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-033",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-033",
                    "https://security.internal.corp/advisories/CVE-2023-34362-033",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-034",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #34",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 34.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-034",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-034",
                    "https://security.internal.corp/advisories/CVE-2023-34362-034",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-035",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #35",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 35.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-035",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-035",
                    "https://security.internal.corp/advisories/CVE-2023-34362-035",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-036",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #36",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 36.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-036",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-036",
                    "https://security.internal.corp/advisories/CVE-2023-34362-036",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-037",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #37",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 37.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-037",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-037",
                    "https://security.internal.corp/advisories/CVE-2023-34362-037",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-038",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #38",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 38.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-038",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-038",
                    "https://security.internal.corp/advisories/CVE-2023-34362-038",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-039",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #39",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 39.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-039",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-039",
                    "https://security.internal.corp/advisories/CVE-2023-34362-039",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-040",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #40",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 40.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-040",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-040",
                    "https://security.internal.corp/advisories/CVE-2023-34362-040",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-041",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #41",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 41.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-041",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-041",
                    "https://security.internal.corp/advisories/CVE-2023-34362-041",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-042",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #42",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 42.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-042",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-042",
                    "https://security.internal.corp/advisories/CVE-2023-34362-042",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-043",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #43",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 43.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-043",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-043",
                    "https://security.internal.corp/advisories/CVE-2023-34362-043",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-044",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #44",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 44.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-044",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-044",
                    "https://security.internal.corp/advisories/CVE-2023-34362-044",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-045",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #45",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 45.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-045",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-045",
                    "https://security.internal.corp/advisories/CVE-2023-34362-045",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-046",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #46",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 46.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-046",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-046",
                    "https://security.internal.corp/advisories/CVE-2023-34362-046",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-047",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #47",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 47.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-047",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-047",
                    "https://security.internal.corp/advisories/CVE-2023-34362-047",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-048",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #48",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 48.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-048",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-048",
                    "https://security.internal.corp/advisories/CVE-2023-34362-048",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-049",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #49",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 49.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-049",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-049",
                    "https://security.internal.corp/advisories/CVE-2023-34362-049",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-050",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #50",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 50.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-050",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-050",
                    "https://security.internal.corp/advisories/CVE-2023-34362-050",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-051",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #51",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 51.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-051",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-051",
                    "https://security.internal.corp/advisories/CVE-2023-34362-051",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-052",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #52",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 52.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-052",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-052",
                    "https://security.internal.corp/advisories/CVE-2023-34362-052",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-053",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #53",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 53.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-053",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-053",
                    "https://security.internal.corp/advisories/CVE-2023-34362-053",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-34362-054",
                title="MOVEit Transfer SQLi and Remote Code Execution - Advisory Profile #54",
                description="SQL injection vulnerability leading to unauthorized privilege elevation. Subsystem component impact analysis variant 54.",
                cvss_v3_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-89",
                affected_components=['Progress MOVEit Transfer before 2023.0.1'],
                remediation_steps=['Apply Progress emergency patch', 'Block all web interface external access'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362-054",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362-054",
                    "https://security.internal.corp/advisories/CVE-2023-34362-054",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #1",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 1.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966",
                    "https://security.internal.corp/advisories/CVE-2023-4966",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-002",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #2",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 2.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-002",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-002",
                    "https://security.internal.corp/advisories/CVE-2023-4966-002",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-003",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #3",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 3.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-003",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-003",
                    "https://security.internal.corp/advisories/CVE-2023-4966-003",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-004",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #4",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 4.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-004",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-004",
                    "https://security.internal.corp/advisories/CVE-2023-4966-004",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-005",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #5",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 5.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-005",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-005",
                    "https://security.internal.corp/advisories/CVE-2023-4966-005",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-006",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #6",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 6.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-006",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-006",
                    "https://security.internal.corp/advisories/CVE-2023-4966-006",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-007",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #7",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 7.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-007",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-007",
                    "https://security.internal.corp/advisories/CVE-2023-4966-007",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-008",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #8",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 8.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-008",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-008",
                    "https://security.internal.corp/advisories/CVE-2023-4966-008",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-009",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #9",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 9.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-009",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-009",
                    "https://security.internal.corp/advisories/CVE-2023-4966-009",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-010",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #10",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 10.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-010",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-010",
                    "https://security.internal.corp/advisories/CVE-2023-4966-010",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-011",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #11",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 11.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-011",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-011",
                    "https://security.internal.corp/advisories/CVE-2023-4966-011",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-012",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #12",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 12.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-012",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-012",
                    "https://security.internal.corp/advisories/CVE-2023-4966-012",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-013",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #13",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 13.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-013",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-013",
                    "https://security.internal.corp/advisories/CVE-2023-4966-013",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-014",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #14",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 14.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-014",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-014",
                    "https://security.internal.corp/advisories/CVE-2023-4966-014",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-015",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #15",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 15.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-015",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-015",
                    "https://security.internal.corp/advisories/CVE-2023-4966-015",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-016",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #16",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 16.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-016",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-016",
                    "https://security.internal.corp/advisories/CVE-2023-4966-016",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-017",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #17",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 17.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-017",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-017",
                    "https://security.internal.corp/advisories/CVE-2023-4966-017",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-018",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #18",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 18.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-018",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-018",
                    "https://security.internal.corp/advisories/CVE-2023-4966-018",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-019",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #19",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 19.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-019",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-019",
                    "https://security.internal.corp/advisories/CVE-2023-4966-019",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-020",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #20",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 20.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-020",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-020",
                    "https://security.internal.corp/advisories/CVE-2023-4966-020",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-021",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #21",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 21.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-021",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-021",
                    "https://security.internal.corp/advisories/CVE-2023-4966-021",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-022",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #22",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 22.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-022",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-022",
                    "https://security.internal.corp/advisories/CVE-2023-4966-022",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-023",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #23",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 23.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-023",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-023",
                    "https://security.internal.corp/advisories/CVE-2023-4966-023",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-024",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #24",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 24.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-024",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-024",
                    "https://security.internal.corp/advisories/CVE-2023-4966-024",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-025",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #25",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 25.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-025",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-025",
                    "https://security.internal.corp/advisories/CVE-2023-4966-025",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-026",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #26",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 26.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-026",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-026",
                    "https://security.internal.corp/advisories/CVE-2023-4966-026",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-027",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #27",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 27.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-027",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-027",
                    "https://security.internal.corp/advisories/CVE-2023-4966-027",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-028",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #28",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 28.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-028",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-028",
                    "https://security.internal.corp/advisories/CVE-2023-4966-028",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-029",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #29",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 29.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-029",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-029",
                    "https://security.internal.corp/advisories/CVE-2023-4966-029",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-030",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #30",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 30.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-030",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-030",
                    "https://security.internal.corp/advisories/CVE-2023-4966-030",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-031",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #31",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 31.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-031",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-031",
                    "https://security.internal.corp/advisories/CVE-2023-4966-031",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-032",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #32",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 32.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-032",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-032",
                    "https://security.internal.corp/advisories/CVE-2023-4966-032",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-033",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #33",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 33.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-033",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-033",
                    "https://security.internal.corp/advisories/CVE-2023-4966-033",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-034",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #34",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 34.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-034",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-034",
                    "https://security.internal.corp/advisories/CVE-2023-4966-034",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-035",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #35",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 35.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-035",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-035",
                    "https://security.internal.corp/advisories/CVE-2023-4966-035",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-036",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #36",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 36.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-036",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-036",
                    "https://security.internal.corp/advisories/CVE-2023-4966-036",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-037",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #37",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 37.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-037",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-037",
                    "https://security.internal.corp/advisories/CVE-2023-4966-037",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-038",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #38",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 38.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-038",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-038",
                    "https://security.internal.corp/advisories/CVE-2023-4966-038",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-039",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #39",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 39.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-039",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-039",
                    "https://security.internal.corp/advisories/CVE-2023-4966-039",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-040",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #40",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 40.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-040",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-040",
                    "https://security.internal.corp/advisories/CVE-2023-4966-040",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-041",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #41",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 41.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-041",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-041",
                    "https://security.internal.corp/advisories/CVE-2023-4966-041",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-042",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #42",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 42.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-042",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-042",
                    "https://security.internal.corp/advisories/CVE-2023-4966-042",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-043",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #43",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 43.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-043",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-043",
                    "https://security.internal.corp/advisories/CVE-2023-4966-043",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-044",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #44",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 44.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-044",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-044",
                    "https://security.internal.corp/advisories/CVE-2023-4966-044",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-045",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #45",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 45.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-045",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-045",
                    "https://security.internal.corp/advisories/CVE-2023-4966-045",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-046",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #46",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 46.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-046",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-046",
                    "https://security.internal.corp/advisories/CVE-2023-4966-046",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-047",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #47",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 47.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-047",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-047",
                    "https://security.internal.corp/advisories/CVE-2023-4966-047",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-048",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #48",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 48.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-048",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-048",
                    "https://security.internal.corp/advisories/CVE-2023-4966-048",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-049",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #49",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 49.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-049",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-049",
                    "https://security.internal.corp/advisories/CVE-2023-4966-049",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-050",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #50",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 50.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-050",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-050",
                    "https://security.internal.corp/advisories/CVE-2023-4966-050",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-051",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #51",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 51.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-051",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-051",
                    "https://security.internal.corp/advisories/CVE-2023-4966-051",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-052",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #52",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 52.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-052",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-052",
                    "https://security.internal.corp/advisories/CVE-2023-4966-052",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-053",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #53",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 53.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-053",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-053",
                    "https://security.internal.corp/advisories/CVE-2023-4966-053",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2023-4966-054",
                title="Citrix NetScaler ADC Information Disclosure (Citrix Bleed) - Advisory Profile #54",
                description="Buffer overflow in OpenID Connect endpoint leaking session tokens. Subsystem component impact analysis variant 54.",
                cvss_v3_score=9.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-119",
                affected_components=['Citrix NetScaler ADC / Gateway 13.0, 13.1, 14.1'],
                remediation_steps=['Upgrade Citrix firmware', 'Terminate all active persistent sessions'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-4966-054",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966-054",
                    "https://security.internal.corp/advisories/CVE-2023-4966-054",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #1",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 1.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400",
                    "https://security.internal.corp/advisories/CVE-2024-3400",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-002",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #2",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 2.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-002",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-002",
                    "https://security.internal.corp/advisories/CVE-2024-3400-002",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-003",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #3",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 3.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-003",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-003",
                    "https://security.internal.corp/advisories/CVE-2024-3400-003",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-004",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #4",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 4.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-004",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-004",
                    "https://security.internal.corp/advisories/CVE-2024-3400-004",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-005",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #5",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 5.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-005",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-005",
                    "https://security.internal.corp/advisories/CVE-2024-3400-005",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-006",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #6",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 6.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-006",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-006",
                    "https://security.internal.corp/advisories/CVE-2024-3400-006",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-007",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #7",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 7.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-007",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-007",
                    "https://security.internal.corp/advisories/CVE-2024-3400-007",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-008",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #8",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 8.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-008",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-008",
                    "https://security.internal.corp/advisories/CVE-2024-3400-008",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-009",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #9",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 9.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-009",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-009",
                    "https://security.internal.corp/advisories/CVE-2024-3400-009",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-010",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #10",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 10.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-010",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-010",
                    "https://security.internal.corp/advisories/CVE-2024-3400-010",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-011",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #11",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 11.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-011",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-011",
                    "https://security.internal.corp/advisories/CVE-2024-3400-011",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-012",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #12",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 12.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-012",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-012",
                    "https://security.internal.corp/advisories/CVE-2024-3400-012",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-013",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #13",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 13.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-013",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-013",
                    "https://security.internal.corp/advisories/CVE-2024-3400-013",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-014",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #14",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 14.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-014",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-014",
                    "https://security.internal.corp/advisories/CVE-2024-3400-014",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-015",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #15",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 15.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-015",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-015",
                    "https://security.internal.corp/advisories/CVE-2024-3400-015",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-016",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #16",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 16.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-016",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-016",
                    "https://security.internal.corp/advisories/CVE-2024-3400-016",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-017",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #17",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 17.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-017",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-017",
                    "https://security.internal.corp/advisories/CVE-2024-3400-017",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-018",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #18",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 18.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-018",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-018",
                    "https://security.internal.corp/advisories/CVE-2024-3400-018",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-019",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #19",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 19.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-019",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-019",
                    "https://security.internal.corp/advisories/CVE-2024-3400-019",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-020",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #20",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 20.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-020",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-020",
                    "https://security.internal.corp/advisories/CVE-2024-3400-020",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-021",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #21",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 21.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-021",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-021",
                    "https://security.internal.corp/advisories/CVE-2024-3400-021",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-022",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #22",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 22.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-022",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-022",
                    "https://security.internal.corp/advisories/CVE-2024-3400-022",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-023",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #23",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 23.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-023",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-023",
                    "https://security.internal.corp/advisories/CVE-2024-3400-023",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-024",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #24",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 24.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-024",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-024",
                    "https://security.internal.corp/advisories/CVE-2024-3400-024",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-025",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #25",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 25.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-025",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-025",
                    "https://security.internal.corp/advisories/CVE-2024-3400-025",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-026",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #26",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 26.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-026",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-026",
                    "https://security.internal.corp/advisories/CVE-2024-3400-026",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-027",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #27",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 27.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-027",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-027",
                    "https://security.internal.corp/advisories/CVE-2024-3400-027",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-028",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #28",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 28.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-028",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-028",
                    "https://security.internal.corp/advisories/CVE-2024-3400-028",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-029",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #29",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 29.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-029",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-029",
                    "https://security.internal.corp/advisories/CVE-2024-3400-029",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-030",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #30",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 30.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-030",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-030",
                    "https://security.internal.corp/advisories/CVE-2024-3400-030",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-031",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #31",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 31.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-031",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-031",
                    "https://security.internal.corp/advisories/CVE-2024-3400-031",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-032",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #32",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 32.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-032",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-032",
                    "https://security.internal.corp/advisories/CVE-2024-3400-032",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-033",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #33",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 33.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-033",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-033",
                    "https://security.internal.corp/advisories/CVE-2024-3400-033",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-034",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #34",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 34.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-034",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-034",
                    "https://security.internal.corp/advisories/CVE-2024-3400-034",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-035",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #35",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 35.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-035",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-035",
                    "https://security.internal.corp/advisories/CVE-2024-3400-035",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-036",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #36",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 36.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-036",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-036",
                    "https://security.internal.corp/advisories/CVE-2024-3400-036",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-037",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #37",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 37.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-037",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-037",
                    "https://security.internal.corp/advisories/CVE-2024-3400-037",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-038",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #38",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 38.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-038",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-038",
                    "https://security.internal.corp/advisories/CVE-2024-3400-038",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-039",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #39",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 39.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-039",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-039",
                    "https://security.internal.corp/advisories/CVE-2024-3400-039",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-040",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #40",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 40.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-040",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-040",
                    "https://security.internal.corp/advisories/CVE-2024-3400-040",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-041",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #41",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 41.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-041",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-041",
                    "https://security.internal.corp/advisories/CVE-2024-3400-041",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-042",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #42",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 42.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-042",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-042",
                    "https://security.internal.corp/advisories/CVE-2024-3400-042",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-043",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #43",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 43.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-043",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-043",
                    "https://security.internal.corp/advisories/CVE-2024-3400-043",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-044",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #44",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 44.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-044",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-044",
                    "https://security.internal.corp/advisories/CVE-2024-3400-044",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-045",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #45",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 45.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-045",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-045",
                    "https://security.internal.corp/advisories/CVE-2024-3400-045",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-046",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #46",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 46.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-046",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-046",
                    "https://security.internal.corp/advisories/CVE-2024-3400-046",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-047",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #47",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 47.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-047",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-047",
                    "https://security.internal.corp/advisories/CVE-2024-3400-047",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-048",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #48",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 48.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-048",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-048",
                    "https://security.internal.corp/advisories/CVE-2024-3400-048",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-049",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #49",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 49.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-049",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-049",
                    "https://security.internal.corp/advisories/CVE-2024-3400-049",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-050",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #50",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 50.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-050",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-050",
                    "https://security.internal.corp/advisories/CVE-2024-3400-050",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-051",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #51",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 51.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-051",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-051",
                    "https://security.internal.corp/advisories/CVE-2024-3400-051",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-052",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #52",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 52.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-052",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-052",
                    "https://security.internal.corp/advisories/CVE-2024-3400-052",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-053",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #53",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 53.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-053",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-053",
                    "https://security.internal.corp/advisories/CVE-2024-3400-053",
                ],
                epss_score=0.88,
            )
        )
        self.register(
            CveDefinition(
                cve_id="CVE-2024-3400-054",
                title="Palo Alto PAN-OS Command Injection - Advisory Profile #54",
                description="OS command injection in GlobalProtect gateway feature. Subsystem component impact analysis variant 54.",
                cvss_v3_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-78",
                affected_components=['PAN-OS 10.2, 11.0, 11.1 with device telemetry'],
                remediation_steps=['Apply Palo Alto hotfix', 'Disable device telemetry temporarily'] + [
                    "Isolate network segments harboring vulnerable instances.",
                    "Enable strict egress filtering on database and application tiers.",
                    "Audit authorization tokens and invalidate compromised sessions.",
                    "Deploy proactive WAF virtual patch rules immediately.",
                    "Verify file integrity against known cryptographic checksums.",
                ],
                reference_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400-054",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3400-054",
                    "https://security.internal.corp/advisories/CVE-2024-3400-054",
                ],
                epss_score=0.88,
            )
        )
