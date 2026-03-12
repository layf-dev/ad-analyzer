from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ZipLimits:
    max_archive_size_mb: int = 200
    max_files: int = 2000
    max_unpacked_size_mb: int = 1024
    allowed_extensions: tuple[str, ...] = (".json", ".txt")

    @property
    def max_archive_size_bytes(self) -> int:
        return self.max_archive_size_mb * 1024 * 1024

    @property
    def max_unpacked_size_bytes(self) -> int:
        return self.max_unpacked_size_mb * 1024 * 1024


@dataclass(frozen=True)
class OllamaConfig:
    host: str = "http://127.0.0.1:11434"
    model: str = "llama3.1:8b"
    timeout_seconds: int = 40


@dataclass(frozen=True)
class RiskScoringConfig:
    severity_base: dict[str, int] = field(
        default_factory=lambda: {
            "CRITICAL": 90,
            "HIGH": 75,
            "MEDIUM": 55,
            "LOW": 30,
        }
    )
    category_ease: dict[str, int] = field(
        default_factory=lambda: {
            "DCSYNC": 95,
            "ACL": 85,
            "GROUP_PRIVILEGE": 80,
            "ADMINCOUNT": 45,
        }
    )
    default_base: int = 40
    default_ease: int = 55
    blend_base_weight: float = 0.7
    blend_ease_weight: float = 0.3
    affected_object_bonus_step: int = 2
    affected_object_bonus_cap: int = 10
    group_path_penalty_step: int = 2
    group_path_penalty_cap: int = 10
    priority_thresholds: dict[str, int] = field(
        default_factory=lambda: {
            "P1": 85,
            "P2": 70,
            "P3": 50,
        }
    )


@dataclass(frozen=True)
class AnalyzerConfig:
    zip_limits: ZipLimits = field(default_factory=ZipLimits)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    risk_scoring: RiskScoringConfig = field(default_factory=RiskScoringConfig)


def ensure_output_dirs(out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    unpacked = out_dir / "unpacked"
    artifacts = out_dir / "artifacts"
    unpacked.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    return {"out": out_dir, "unpacked": unpacked, "artifacts": artifacts}


def _read_json_file(path: Path) -> Any:
    last_exc: Exception | None = None
    for encoding in ("utf-8", "utf-8-sig"):
        try:
            return json.loads(path.read_text(encoding=encoding))
        except OSError as exc:
            raise ValueError(f"Unable to read JSON config: {exc}") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_exc = exc
    raise ValueError(f"Unable to parse JSON config: {last_exc}")


def load_risk_scoring_config(path: Path | None) -> RiskScoringConfig:
    default = RiskScoringConfig()
    if not path:
        return default

    payload = _read_json_file(path)
    if not isinstance(payload, dict):
        raise ValueError("Risk config must be a JSON object.")

    def _dict_int(source: Any, fallback: dict[str, int]) -> dict[str, int]:
        if not isinstance(source, dict):
            return dict(fallback)
        out = dict(fallback)
        for key, value in source.items():
            out[str(key).upper()] = int(value)
        return out

    return RiskScoringConfig(
        severity_base=_dict_int(payload.get("severity_base"), default.severity_base),
        category_ease=_dict_int(payload.get("category_ease"), default.category_ease),
        default_base=int(payload.get("default_base", default.default_base)),
        default_ease=int(payload.get("default_ease", default.default_ease)),
        blend_base_weight=float(payload.get("blend_base_weight", default.blend_base_weight)),
        blend_ease_weight=float(payload.get("blend_ease_weight", default.blend_ease_weight)),
        affected_object_bonus_step=int(
            payload.get("affected_object_bonus_step", default.affected_object_bonus_step)
        ),
        affected_object_bonus_cap=int(
            payload.get("affected_object_bonus_cap", default.affected_object_bonus_cap)
        ),
        group_path_penalty_step=int(
            payload.get("group_path_penalty_step", default.group_path_penalty_step)
        ),
        group_path_penalty_cap=int(
            payload.get("group_path_penalty_cap", default.group_path_penalty_cap)
        ),
        priority_thresholds=_dict_int(
            payload.get("priority_thresholds"), default.priority_thresholds
        ),
    )
