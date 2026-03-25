from __future__ import annotations

from ad_analyzer.io.strict_input import collect_strict_input_violations


def test_strict_input_collects_critical_data_issues() -> None:
    violations = collect_strict_input_violations(
        load_warnings=[
            "Invalid JSON skipped: users.json: boom",
            "Dataset 'users' not found, continuing with partial data.",
            "Unknown JSON file skipped: gpos.json",
        ],
        normalize_warnings=[
            "Skip users[0] without identifier.",
        ],
    )

    assert "Invalid JSON skipped: users.json: boom" in violations
    assert "Dataset 'users' not found, continuing with partial data." in violations
    assert "Skip users[0] without identifier." in violations
    assert "Unknown JSON file skipped: gpos.json" not in violations


def test_strict_input_ignores_non_critical_missing_optional_datasets() -> None:
    violations = collect_strict_input_violations(
        load_warnings=[
            "Dataset 'sessions' not found, continuing with partial data.",
            "Dataset 'acls' not found, continuing with partial data.",
        ],
        normalize_warnings=[],
    )

    assert violations == []
