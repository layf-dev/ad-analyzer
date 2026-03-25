from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ad_analyzer.cli import _sort_findings, app
from ad_analyzer.model.types import AffectedObject, Evidence, Severity, create_finding


runner = CliRunner()


def _mk_finding(title: str, category: str, severity: Severity, object_id: str) -> dict:
    finding = create_finding(
        title=title,
        severity=severity,
        category=category,
        affected_objects=[AffectedObject(id=object_id, type="USER", name=object_id)],
        evidence=Evidence(edges=[], path=[], raw_refs=[]),
        why_risky="risk",
        how_to_verify=["verify"],
        fix_plan=["fix"],
    )
    return finding.to_dict()


def test_diff_returns_friendly_error_for_invalid_findings_json(tmp_path: Path) -> None:
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    old_dir.mkdir(parents=True, exist_ok=True)
    new_dir.mkdir(parents=True, exist_ok=True)
    (old_dir / "findings.json").write_text('{"oops": 1}', encoding="utf-8")
    (new_dir / "findings.json").write_text('{"oops": 1}', encoding="utf-8")

    result = runner.invoke(app, ["diff", str(old_dir), str(new_dir)])

    assert result.exit_code == 1
    assert "Invalid findings file:" in result.output
    assert "findings.json must contain a list" in result.output


def test_report_rewrites_findings_json_after_allowlist(tmp_path: Path) -> None:
    findings = [
        _mk_finding("acl issue", "ACL", Severity.HIGH, "U1"),
        _mk_finding("admin count", "ADMINCOUNT", Severity.MEDIUM, "U2"),
    ]
    (tmp_path / "findings.json").write_text(
        json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (tmp_path / "summary.json").write_text("{}", encoding="utf-8")
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text('{"categories":["ACL"]}', encoding="utf-8")

    result = runner.invoke(app, ["report", str(tmp_path), "--allowlist", str(allowlist)])

    assert result.exit_code == 0
    updated_findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    updated_summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert len(updated_findings) == 1
    assert updated_findings[0]["category"] == "ADMINCOUNT"
    assert updated_summary["total"] == 1
    assert updated_summary["suppressed"] == 1


def test_sort_findings_uses_severity_order_for_equal_risk() -> None:
    critical = create_finding(
        title="critical issue",
        severity=Severity.CRITICAL,
        category="ACL",
        affected_objects=[AffectedObject(id="U1", type="USER", name="U1")],
        evidence=Evidence(edges=[], path=[], raw_refs=[]),
        why_risky="risk",
        how_to_verify=["verify"],
        fix_plan=["fix"],
        risk_score=80,
        remediation_priority="P3",
    )
    high = create_finding(
        title="high issue",
        severity=Severity.HIGH,
        category="ACL",
        affected_objects=[AffectedObject(id="U2", type="USER", name="U2")],
        evidence=Evidence(edges=[], path=[], raw_refs=[]),
        why_risky="risk",
        how_to_verify=["verify"],
        fix_plan=["fix"],
        risk_score=80,
        remediation_priority="P1",
    )
    findings = [high, critical]

    _sort_findings(findings)

    assert findings[0].severity == Severity.CRITICAL
