from __future__ import annotations

from collections.abc import Sequence


CORE_REQUIRED_DATASETS = ("users", "groups", "computers", "domains")


def collect_strict_input_violations(
    *,
    load_warnings: Sequence[str],
    normalize_warnings: Sequence[str],
) -> list[str]:
    violations: list[str] = []

    for warning in load_warnings:
        if warning.startswith("No JSON files found after extraction."):
            violations.append(warning)
        elif warning.startswith("Invalid JSON skipped:"):
            violations.append(warning)

    for dataset in CORE_REQUIRED_DATASETS:
        marker = f"Dataset '{dataset}' not found, continuing with partial data."
        if marker in load_warnings:
            violations.append(marker)

    for warning in normalize_warnings:
        if warning.startswith("Skip ") and "without identifier." in warning:
            violations.append(warning)

    return violations
