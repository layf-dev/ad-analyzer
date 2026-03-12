from __future__ import annotations

import csv
from pathlib import Path

from ad_analyzer.model.types import Finding


def write_findings_csv(findings: list[Finding], out_dir: Path) -> Path:
    path = out_dir / "findings.csv"
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "id",
                "severity",
                "risk_score",
                "remediation_priority",
                "category",
                "mitre_attack",
                "title",
                "affected_objects",
            ]
        )
        for finding in findings:
            affected = "; ".join(
                f"{obj.id}:{obj.type}:{obj.name}" for obj in finding.affected_objects
            )
            mitre = "; ".join(
                f"{ref.tactic_id}/{ref.technique_id}:{ref.technique_name}"
                for ref in finding.mitre_attack
            )
            writer.writerow(
                [
                    finding.id,
                    finding.severity.value,
                    finding.risk_score,
                    finding.remediation_priority,
                    finding.category,
                    mitre,
                    finding.title,
                    affected,
                ]
            )
    return path
