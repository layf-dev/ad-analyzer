from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from ad_analyzer.model.types import Finding, finding_fingerprint, finding_from_dict


def _normalize_title_for_fallback(title: str) -> str:
    return " ".join(title.lower().strip().split())


def _correlation_key(finding: Finding) -> str:
    return finding_fingerprint(
        category=finding.category,
        title=finding.title,
        affected_objects=finding.affected_objects,
        evidence=finding.evidence,
    )


def _legacy_fallback_key(finding: Finding) -> str:
    affected_ids = ",".join(sorted(obj.id for obj in finding.affected_objects))
    return f"{finding.category.lower()}|{_normalize_title_for_fallback(finding.title)}|{affected_ids}"


@dataclass(slots=True)
class DiffResult:
    new: list[Finding]
    resolved: list[Finding]
    persistent: list[Finding]
    severity_changed: list[dict[str, str]]

    def to_dict(self) -> dict:
        return {
            "summary": {
                "new_count": len(self.new),
                "resolved_count": len(self.resolved),
                "persistent_count": len(self.persistent),
                "severity_changed_count": len(self.severity_changed),
            },
            "new": [x.to_dict() for x in self.new],
            "resolved": [x.to_dict() for x in self.resolved],
            "persistent": [x.to_dict() for x in self.persistent],
            "severity_changed": self.severity_changed,
        }


def load_findings_file(path: Path) -> list[Finding]:
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("findings.json must contain a list")
    return [finding_from_dict(x) for x in rows]


def _bucket_by_key(findings: list[Finding], use_fallback: bool = False) -> dict[str, list[Finding]]:
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        key = _legacy_fallback_key(finding) if use_fallback else _correlation_key(finding)
        buckets[key].append(finding)
    for rows in buckets.values():
        rows.sort(key=lambda x: (x.id, x.title, x.severity.value))
    return dict(buckets)


def _match_buckets(
    old_buckets: dict[str, list[Finding]],
    new_buckets: dict[str, list[Finding]],
) -> tuple[list[Finding], list[Finding], list[tuple[str, Finding, Finding]], list[str]]:
    old_only_keys = sorted(set(old_buckets) - set(new_buckets))
    new_only_keys = sorted(set(new_buckets) - set(old_buckets))
    common_keys = sorted(set(old_buckets) & set(new_buckets))

    resolved: list[Finding] = [item for key in old_only_keys for item in old_buckets[key]]
    new_items: list[Finding] = [item for key in new_only_keys for item in new_buckets[key]]
    paired: list[tuple[str, Finding, Finding]] = []

    for key in common_keys:
        old_rows = old_buckets[key]
        new_rows = new_buckets[key]
        overlap = min(len(old_rows), len(new_rows))
        for idx in range(overlap):
            paired.append((key, old_rows[idx], new_rows[idx]))
        if len(old_rows) > overlap:
            resolved.extend(old_rows[overlap:])
        if len(new_rows) > overlap:
            new_items.extend(new_rows[overlap:])

    return new_items, resolved, paired, common_keys


def compare_findings(old_findings: list[Finding], new_findings: list[Finding]) -> DiffResult:
    old_buckets = _bucket_by_key(old_findings, use_fallback=False)
    new_buckets = _bucket_by_key(new_findings, use_fallback=False)
    new_items, resolved_items, paired, _ = _match_buckets(old_buckets, new_buckets)

    # Compatibility path: try to reconcile unmatched tails using legacy key.
    if (new_items or resolved_items) and old_findings and new_findings:
        old_buckets_fb = _bucket_by_key(resolved_items, use_fallback=True)
        new_buckets_fb = _bucket_by_key(new_items, use_fallback=True)
        new_fb, resolved_fb, paired_fb, _ = _match_buckets(old_buckets_fb, new_buckets_fb)
        paired.extend(paired_fb)
        new_items = new_fb
        resolved_items = resolved_fb

    persistent_items = [new_f for _, _, new_f in paired]
    severity_changed: list[dict[str, str]] = []
    for key, old_f, new_f in paired:
        if old_f.severity != new_f.severity:
            severity_changed.append(
                {
                    "signature": key,
                    "title": new_f.title,
                    "old_severity": old_f.severity.value,
                    "new_severity": new_f.severity.value,
                }
            )

    new_items.sort(key=lambda x: (x.severity.value, x.title))
    resolved_items.sort(key=lambda x: (x.severity.value, x.title))
    persistent_items.sort(key=lambda x: (x.severity.value, x.title))

    return DiffResult(
        new=new_items,
        resolved=resolved_items,
        persistent=persistent_items,
        severity_changed=severity_changed,
    )


def render_diff_markdown(diff: DiffResult, out_path: Path) -> Path:
    lines = [
        "# AD Analyzer Diff",
        "",
        "## Summary",
        "",
        f"- New findings: **{len(diff.new)}**",
        f"- Resolved findings: **{len(diff.resolved)}**",
        f"- Persistent findings: **{len(diff.persistent)}**",
        f"- Severity changes: **{len(diff.severity_changed)}**",
        "",
        "## New Findings",
    ]
    if not diff.new:
        lines.append("- none")
    for finding in diff.new:
        lines.append(f"- `{finding.severity.value}` {finding.title}")

    lines.extend(["", "## Resolved Findings"])
    if not diff.resolved:
        lines.append("- none")
    for finding in diff.resolved:
        lines.append(f"- `{finding.severity.value}` {finding.title}")

    lines.extend(["", "## Severity Changes"])
    if not diff.severity_changed:
        lines.append("- none")
    for row in diff.severity_changed:
        lines.append(f"- {row['title']}: `{row['old_severity']}` -> `{row['new_severity']}`")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def write_diff_json(diff: DiffResult, out_path: Path) -> Path:
    out_path.write_text(json.dumps(diff.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path
