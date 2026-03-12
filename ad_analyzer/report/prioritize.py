from __future__ import annotations

from ad_analyzer.config import RiskScoringConfig
from ad_analyzer.model.types import Finding, Severity


def _clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


def priority_from_score(score: int, cfg: RiskScoringConfig) -> str:
    if score >= int(cfg.priority_thresholds.get("P1", 85)):
        return "P1"
    if score >= int(cfg.priority_thresholds.get("P2", 70)):
        return "P2"
    if score >= int(cfg.priority_thresholds.get("P3", 50)):
        return "P3"
    return "P4"


def calculate_risk_score(finding: Finding, cfg: RiskScoringConfig | None = None) -> int:
    cfg = cfg or RiskScoringConfig()
    base = cfg.severity_base.get(finding.severity.value, cfg.default_base)
    ease = cfg.category_ease.get(finding.category.upper(), cfg.default_ease)
    affected_bonus = min(
        cfg.affected_object_bonus_cap,
        max(0, len(finding.affected_objects) - 1) * cfg.affected_object_bonus_step,
    )
    path_penalty = 0
    if finding.category.upper() == "GROUP_PRIVILEGE":
        hops = max(0, len(finding.evidence.path) - 1)
        path_penalty = min(
            cfg.group_path_penalty_cap,
            max(0, hops - 1) * cfg.group_path_penalty_step,
        )

    weight_sum = cfg.blend_base_weight + cfg.blend_ease_weight
    if weight_sum <= 0:
        blended = int(round((base + ease) / 2))
    else:
        blended = int(
            round(
                base * (cfg.blend_base_weight / weight_sum)
                + ease * (cfg.blend_ease_weight / weight_sum)
            )
        )
    return _clamp(blended + affected_bonus - path_penalty)


def enrich_findings_with_priority(
    findings: list[Finding], cfg: RiskScoringConfig | None = None
) -> list[Finding]:
    cfg = cfg or RiskScoringConfig()
    for finding in findings:
        finding.risk_score = calculate_risk_score(finding, cfg=cfg)
        finding.remediation_priority = priority_from_score(finding.risk_score, cfg=cfg)
    return findings
