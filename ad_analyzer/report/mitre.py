from __future__ import annotations

from ad_analyzer.model.types import Finding, MitreAttackRef


CATEGORY_TO_MITRE: dict[str, list[MitreAttackRef]] = {
    "GROUP_PRIVILEGE": [
        MitreAttackRef(
            tactic_id="TA0004",
            tactic_name="Privilege Escalation",
            technique_id="T1078",
            technique_name="Valid Accounts",
        ),
    ],
    "ADMINCOUNT": [
        MitreAttackRef(
            tactic_id="TA0004",
            tactic_name="Privilege Escalation",
            technique_id="T1078",
            technique_name="Valid Accounts",
        ),
    ],
    "ACL": [
        MitreAttackRef(
            tactic_id="TA0003",
            tactic_name="Persistence",
            technique_id="T1098",
            technique_name="Account Manipulation",
        ),
        MitreAttackRef(
            tactic_id="TA0004",
            tactic_name="Privilege Escalation",
            technique_id="T1098",
            technique_name="Account Manipulation",
        ),
    ],
    "DCSYNC": [
        MitreAttackRef(
            tactic_id="TA0006",
            tactic_name="Credential Access",
            technique_id="T1003.006",
            technique_name="OS Credential Dumping: DCSync",
        ),
    ],
}


def mitre_refs_for_category(category: str) -> list[MitreAttackRef]:
    refs = CATEGORY_TO_MITRE.get(category.upper(), [])
    return [
        MitreAttackRef(
            tactic_id=ref.tactic_id,
            tactic_name=ref.tactic_name,
            technique_id=ref.technique_id,
            technique_name=ref.technique_name,
        )
        for ref in refs
    ]


def enrich_findings_with_mitre(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        finding.mitre_attack = mitre_refs_for_category(finding.category)
    return findings

