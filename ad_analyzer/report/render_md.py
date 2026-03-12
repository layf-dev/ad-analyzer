from __future__ import annotations

from pathlib import Path

from ad_analyzer.model.types import Finding


def _render_summary_block(summary: dict) -> str:
    sev = summary["by_severity"]
    prio = summary.get("by_priority", {})
    return (
        "## Severity Summary\n\n"
        f"- Total: **{summary['total']}**\n"
        f"- Suppressed by allowlist: **{summary.get('suppressed', 0)}**\n"
        f"- CRITICAL: **{sev['CRITICAL']}**\n"
        f"- HIGH: **{sev['HIGH']}**\n"
        f"- MEDIUM: **{sev['MEDIUM']}**\n"
        f"- LOW: **{sev['LOW']}**\n"
        f"- Avg risk score: **{summary.get('avg_risk_score', 0)}**\n"
        f"- P1: **{prio.get('P1', 0)}** / P2: **{prio.get('P2', 0)}** / P3: **{prio.get('P3', 0)}** / P4: **{prio.get('P4', 0)}**\n"
    )


def _render_table(findings: list[Finding]) -> str:
    lines = [
        "## Findings Table",
        "",
        "| ID | Severity | Risk | Priority | MITRE | Title |",
        "|---|---|---:|---|---|---|",
    ]
    for f in findings:
        mitre = ", ".join(sorted({ref.technique_id for ref in f.mitre_attack})) or "n/a"
        lines.append(
            f"| `{f.id}` | {f.severity.value} | {f.risk_score} | {f.remediation_priority} | {mitre} | {f.title} |"
        )
    return "\n".join(lines)


def _render_finding(finding: Finding) -> str:
    affected = ", ".join(f"{obj.type}:{obj.name}" for obj in finding.affected_objects) or "n/a"
    evidence_edges = finding.evidence.edges or []
    path = " -> ".join(finding.evidence.path) if finding.evidence.path else "n/a"
    raw_refs = ", ".join(finding.evidence.raw_refs) if finding.evidence.raw_refs else "n/a"
    verify = "\n".join(f"- {s}" for s in finding.how_to_verify) or "- n/a"
    fixes = "\n".join(f"1. {s}" for s in finding.fix_plan) or "1. n/a"
    mitre = (
        "\n".join(
            f"- `{ref.tactic_id}` {ref.tactic_name} / `{ref.technique_id}` {ref.technique_name}"
            for ref in finding.mitre_attack
        )
        or "- n/a"
    )

    parts = [
        f"### {finding.title}",
        "",
        f"- ID: `{finding.id}`",
        f"- Severity: **{finding.severity.value}**",
        f"- Risk score: **{finding.risk_score}**",
        f"- Remediation priority: **{finding.remediation_priority}**",
        f"- Category: `{finding.category}`",
        f"- Affected: {affected}",
        "",
        "**MITRE ATT&CK**",
        "",
        mitre,
        "",
        "**Evidence**",
        "",
        f"- Path: `{path}`",
        f"- Edges: `{evidence_edges}`",
        f"- Raw refs: `{raw_refs}`",
        "",
        f"**Why risky**\n\n{finding.why_risky}",
        "",
        "**How to verify**",
        "",
        verify,
        "",
        "**Fix plan**",
        "",
        fixes,
    ]
    if finding.notes:
        parts.extend(["", f"**Notes**\n\n{finding.notes}"])
    if finding.llm_explanation:
        parts.extend(["", f"**LLM Explanation**\n\n{finding.llm_explanation}"])
    return "\n".join(parts)


def render_markdown_report(findings: list[Finding], summary: dict, out_dir: Path) -> Path:
    report_path = out_dir / "report.md"
    blocks = ["# AD Analyzer Report", "", _render_summary_block(summary), "", _render_table(findings), ""]
    for finding in findings:
        blocks.append(_render_finding(finding))
        blocks.append("")
    report_path.write_text("\n".join(blocks), encoding="utf-8")
    return report_path
