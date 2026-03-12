from __future__ import annotations

import json
from pathlib import Path

from ad_analyzer.model.types import Finding


def build_summary(findings: list[Finding], suppressed_count: int = 0) -> dict:
    summary = {
        "total": len(findings),
        "suppressed": suppressed_count,
        "by_severity": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        },
        "by_priority": {
            "P1": 0,
            "P2": 0,
            "P3": 0,
            "P4": 0,
        },
        "avg_risk_score": 0,
    }
    total_risk = 0
    for finding in findings:
        summary["by_severity"][finding.severity.value] += 1
        summary["by_priority"].setdefault(finding.remediation_priority, 0)
        summary["by_priority"][finding.remediation_priority] += 1
        total_risk += finding.risk_score
    if findings:
        summary["avg_risk_score"] = round(total_risk / len(findings), 2)
    return summary


def write_json_reports(
    findings: list[Finding], out_dir: Path, suppressed_count: int = 0
) -> tuple[Path, Path, dict]:
    findings_path = out_dir / "findings.json"
    summary_path = out_dir / "summary.json"
    summary = build_summary(findings, suppressed_count=suppressed_count)

    findings_path.write_text(
        json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return findings_path, summary_path, summary
