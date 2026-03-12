from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from ad_analyzer.model.normalize import extract_data_records

logger = logging.getLogger(__name__)


EXPECTED_DATASETS = ("users", "groups", "computers", "domains", "sessions", "acls")


def _detect_dataset(file_path: Path) -> str | None:
    name = file_path.name.lower()
    if "user" in name:
        return "users"
    if "group" in name:
        return "groups"
    if "computer" in name:
        return "computers"
    if "domain" in name:
        return "domains"
    if "session" in name:
        return "sessions"
    if "acl" in name:
        return "acls"
    return None


def load_sharphound_jsons(unpacked_dir: Path) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    datasets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    warnings: list[str] = []

    files = sorted(unpacked_dir.rglob("*.json"))
    if not files:
        warnings.append("No JSON files found after extraction.")
        return dict(datasets), warnings

    for file_path in files:
        dataset = _detect_dataset(file_path)
        if not dataset:
            warnings.append(f"Unknown JSON file skipped: {file_path.name}")
            continue
        payload: Any | None = None
        decode_error: Exception | None = None
        for encoding in ("utf-8", "utf-8-sig"):
            try:
                payload = json.loads(file_path.read_text(encoding=encoding))
                decode_error = None
                break
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                decode_error = exc
        if payload is None:
            warnings.append(f"Invalid JSON skipped: {file_path.name}: {decode_error}")
            continue

        records = extract_data_records(payload)
        datasets[dataset].extend(records)
        logger.debug("Loaded %d records from %s into %s", len(records), file_path, dataset)

    for key in EXPECTED_DATASETS:
        if not datasets.get(key):
            warnings.append(f"Dataset '{key}' not found, continuing with partial data.")

    return dict(datasets), warnings
