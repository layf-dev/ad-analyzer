from __future__ import annotations

from pathlib import Path

from ad_analyzer.config import load_risk_scoring_config


def test_load_risk_scoring_config_overrides_values(tmp_path: Path) -> None:
    cfg_path = tmp_path / "risk.json"
    cfg_path.write_text(
        """
{
  "severity_base": {"CRITICAL": 99},
  "category_ease": {"ACL": 66},
  "priority_thresholds": {"P1": 95, "P2": 80, "P3": 60}
}
""".strip(),
        encoding="utf-8",
    )
    cfg = load_risk_scoring_config(cfg_path)
    assert cfg.severity_base["CRITICAL"] == 99
    assert cfg.category_ease["ACL"] == 66
    assert cfg.priority_thresholds["P1"] == 95

