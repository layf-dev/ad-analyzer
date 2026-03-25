from __future__ import annotations

from pathlib import Path

from ad_analyzer.config import RiskScoringConfig
from ad_analyzer.model.types import AffectedObject, Evidence, Severity, create_finding
from ad_analyzer.report.allowlist import apply_allowlist
from ad_analyzer.report.diff import compare_findings
from ad_analyzer.report.mitre import enrich_findings_with_mitre
from ad_analyzer.report.prioritize import enrich_findings_with_priority
from ad_analyzer.report.render_html import render_html_report
from ad_analyzer.report.render_json import build_summary
from ad_analyzer.report.render_pdf import render_pdf_report


def _mk_finding(title: str, severity: Severity, category: str, object_id: str):
    return create_finding(
        title=title,
        severity=severity,
        category=category,
        affected_objects=[AffectedObject(id=object_id, type="USER", name=object_id)],
        evidence=Evidence(edges=[], path=[], raw_refs=[]),
        why_risky="risk",
        how_to_verify=["verify"],
        fix_plan=["fix"],
    )


def test_prioritization_sets_risk_and_priority() -> None:
    finding = _mk_finding("dcsync", Severity.CRITICAL, "DCSYNC", "U1")
    enrich_findings_with_mitre([finding])
    enrich_findings_with_priority([finding])
    assert finding.risk_score >= 85
    assert finding.remediation_priority == "P1"


def test_prioritization_respects_custom_config() -> None:
    finding = _mk_finding("custom", Severity.MEDIUM, "ADMINCOUNT", "U1")
    enrich_findings_with_mitre([finding])
    cfg = RiskScoringConfig(
        severity_base={"CRITICAL": 80, "HIGH": 70, "MEDIUM": 30, "LOW": 20},
        category_ease={"ADMINCOUNT": 20},
        default_base=30,
        default_ease=20,
        blend_base_weight=1.0,
        blend_ease_weight=0.0,
        affected_object_bonus_step=0,
        affected_object_bonus_cap=0,
        group_path_penalty_step=0,
        group_path_penalty_cap=0,
        priority_thresholds={"P1": 90, "P2": 80, "P3": 40},
    )
    enrich_findings_with_priority([finding], cfg=cfg)
    assert finding.risk_score == 30
    assert finding.remediation_priority == "P4"


def test_mitre_mapping_is_applied_by_category() -> None:
    finding = _mk_finding("dcsync", Severity.CRITICAL, "DCSYNC", "U1")
    enrich_findings_with_mitre([finding])
    assert len(finding.mitre_attack) == 1
    assert finding.mitre_attack[0].technique_id == "T1003.006"


def test_allowlist_filters_by_category() -> None:
    f1 = _mk_finding("admin count", Severity.MEDIUM, "ADMINCOUNT", "U1")
    f2 = _mk_finding("acl danger", Severity.HIGH, "ACL", "U2")
    result = apply_allowlist([f1, f2], {"categories": ["ADMINCOUNT"]})
    assert len(result.findings) == 1
    assert result.findings[0].category == "ACL"
    assert len(result.suppressed) == 1


def test_diff_detects_new_and_resolved() -> None:
    old = [_mk_finding("old issue", Severity.MEDIUM, "ACL", "U1")]
    new = [_mk_finding("new issue", Severity.HIGH, "DCSYNC", "U2")]
    diff = compare_findings(old, new)
    assert len(diff.new) == 1
    assert len(diff.resolved) == 1
    assert len(diff.persistent) == 0


def test_finding_id_is_stable_for_same_payload() -> None:
    f1 = _mk_finding("same issue", Severity.HIGH, "ACL", "U1")
    f2 = _mk_finding("same issue", Severity.HIGH, "ACL", "U1")
    assert f1.id == f2.id


def test_diff_matches_equivalent_findings_with_normalized_title() -> None:
    old = [_mk_finding("  ADMIN  Path  ", Severity.HIGH, "ACL", "U1")]
    new = [_mk_finding("admin path", Severity.CRITICAL, "ACL", "U1")]
    diff = compare_findings(old, new)
    assert len(diff.new) == 0
    assert len(diff.resolved) == 0
    assert len(diff.persistent) == 1
    assert len(diff.severity_changed) == 1


def test_diff_matches_equivalent_findings_when_edge_order_changes() -> None:
    old = [
        create_finding(
            title="acl chain",
            severity=Severity.HIGH,
            category="ACL",
            affected_objects=[AffectedObject(id="U1", type="USER", name="U1")],
            evidence=Evidence(
                edges=[
                    {"src_id": "A", "rel_type": "ACL_RIGHT", "dst_id": "B", "rights": ["WriteDacl"]},
                    {"src_id": "C", "rel_type": "ACL_RIGHT", "dst_id": "D", "rights": ["GenericAll"]},
                ],
                path=[],
                raw_refs=[],
            ),
            why_risky="risk",
            how_to_verify=["verify"],
            fix_plan=["fix"],
        )
    ]
    new = [
        create_finding(
            title="acl chain",
            severity=Severity.HIGH,
            category="ACL",
            affected_objects=[AffectedObject(id="U1", type="USER", name="U1")],
            evidence=Evidence(
                edges=[
                    {"src_id": "C", "rel_type": "ACL_RIGHT", "dst_id": "D", "rights": ["GenericAll"]},
                    {"src_id": "A", "rel_type": "ACL_RIGHT", "dst_id": "B", "rights": ["WriteDacl"]},
                ],
                path=[],
                raw_refs=[],
            ),
            why_risky="risk",
            how_to_verify=["verify"],
            fix_plan=["fix"],
        )
    ]
    diff = compare_findings(old, new)
    assert len(diff.new) == 0
    assert len(diff.resolved) == 0
    assert len(diff.persistent) == 1


def test_pdf_report_is_generated(tmp_path: Path) -> None:
    finding = _mk_finding("pdf finding", Severity.HIGH, "ACL", "U1")
    enrich_findings_with_mitre([finding])
    enrich_findings_with_priority([finding])
    summary = build_summary([finding], suppressed_count=0)

    pdf_path = render_pdf_report([finding], summary, tmp_path)

    assert pdf_path.exists()
    payload = pdf_path.read_bytes()
    assert payload.startswith(b"%PDF-")
    assert b"%%EOF" in payload[-1024:]


def test_html_report_escapes_untrusted_fields(tmp_path: Path) -> None:
    finding = _mk_finding("<script>alert(1)</script>", Severity.HIGH, "ACL", "U1")
    summary = build_summary([finding], suppressed_count=0)

    html_path = render_html_report([finding], summary, tmp_path)
    html = html_path.read_text(encoding="utf-8")

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
