from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ad_analyzer.model.types import Finding


@dataclass(slots=True)
class AllowlistResult:
    findings: list[Finding]
    suppressed: list[Finding]


def load_allowlist(path: Path) -> dict[str, Any]:
    data: Any | None = None
    last_exc: Exception | None = None
    for encoding in ("utf-8", "utf-8-sig"):
        try:
            data = json.loads(path.read_text(encoding=encoding))
            last_exc = None
            break
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_exc = exc
    if data is None:
        raise ValueError(f"Unable to parse allowlist JSON: {last_exc}")
    if not isinstance(data, dict):
        raise ValueError("Allowlist must be a JSON object.")
    return data


def _normalize_top_level_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for rule in data.get("rules", []):
        if isinstance(rule, dict):
            rules.append(rule)

    for finding_id in data.get("ids", []):
        rules.append({"id": str(finding_id)})
    for category in data.get("categories", []):
        rules.append({"category": str(category)})
    for token in data.get("title_contains", []):
        rules.append({"title_contains": str(token)})
    for object_id in data.get("affected_object_ids", []):
        rules.append({"affected_object_id": str(object_id)})
    return rules


def _rule_match(finding: Finding, rule: dict[str, Any]) -> bool:
    checks: list[bool] = []
    if "id" in rule:
        checks.append(finding.id == str(rule["id"]))
    if "category" in rule:
        checks.append(finding.category.lower() == str(rule["category"]).lower())
    if "severity" in rule:
        checks.append(finding.severity.value.lower() == str(rule["severity"]).lower())
    if "title_contains" in rule:
        checks.append(str(rule["title_contains"]).lower() in finding.title.lower())
    if "affected_object_id" in rule:
        target = str(rule["affected_object_id"])
        checks.append(any(obj.id == target for obj in finding.affected_objects))

    return bool(checks) and all(checks)


def apply_allowlist(findings: list[Finding], allowlist_data: dict[str, Any]) -> AllowlistResult:
    rules = _normalize_top_level_rules(allowlist_data)
    if not rules:
        return AllowlistResult(findings=list(findings), suppressed=[])

    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        if any(_rule_match(finding, rule) for rule in rules):
            suppressed.append(finding)
        else:
            kept.append(finding)
    return AllowlistResult(findings=kept, suppressed=suppressed)
