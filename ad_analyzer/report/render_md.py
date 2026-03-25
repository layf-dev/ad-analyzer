from __future__ import annotations

from pathlib import Path

from ad_analyzer.model.types import Finding


def _render_summary_block(summary: dict) -> str:
    sev = summary["by_severity"]
    prio = summary.get("by_priority", {})
    return (
        "## Сводка по критичности\n\n"
        f"- Всего: **{summary['total']}**\n"
        f"- Подавлено allowlist: **{summary.get('suppressed', 0)}**\n"
        f"- CRITICAL: **{sev['CRITICAL']}**\n"
        f"- HIGH: **{sev['HIGH']}**\n"
        f"- MEDIUM: **{sev['MEDIUM']}**\n"
        f"- LOW: **{sev['LOW']}**\n"
        f"- Средний risk score: **{summary.get('avg_risk_score', 0)}**\n"
        f"- P1: **{prio.get('P1', 0)}** / P2: **{prio.get('P2', 0)}** / P3: **{prio.get('P3', 0)}** / P4: **{prio.get('P4', 0)}**\n"
    )


def _render_table(findings: list[Finding]) -> str:
    lines = [
        "## Таблица находок",
        "",
        "| ID | Критичность | Risk | Приоритет | MITRE | Заголовок |",
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
        f"- Критичность: **{finding.severity.value}**",
        f"- Risk score: **{finding.risk_score}**",
        f"- Приоритет исправления: **{finding.remediation_priority}**",
        f"- Категория: `{finding.category}`",
        f"- Затронутые объекты: {affected}",
        "",
        "**MITRE ATT&CK**",
        "",
        mitre,
        "",
        "**Доказательства**",
        "",
        f"- Путь: `{path}`",
        f"- Рёбра: `{evidence_edges}`",
        f"- Ссылки на источники: `{raw_refs}`",
        "",
        f"**Почему это риск**\n\n{finding.why_risky}",
        "",
        "**Как проверить**",
        "",
        verify,
        "",
        "**План исправления**",
        "",
        fixes,
    ]
    if finding.notes:
        parts.extend(["", f"**Примечания**\n\n{finding.notes}"])
    if finding.llm_explanation:
        parts.extend(["", f"**Пояснение LLM**\n\n{finding.llm_explanation}"])
    return "\n".join(parts)


def render_markdown_report(findings: list[Finding], summary: dict, out_dir: Path) -> Path:
    report_path = out_dir / "report.md"
    blocks = ["# Отчёт AD Analyzer", "", _render_summary_block(summary), "", _render_table(findings), ""]
    for finding in findings:
        blocks.append(_render_finding(finding))
        blocks.append("")
    report_path.write_text("\n".join(blocks), encoding="utf-8")
    return report_path
