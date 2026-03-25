from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from ad_analyzer.config import ZipLimits
from ad_analyzer.io.zip_safe import ZipSafetyError, reset_directory, safe_extract_zip


def _make_zip(path: Path, files: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)


def test_zip_slip_blocked(tmp_path: Path) -> None:
    archive = tmp_path / "slip.zip"
    _make_zip(archive, {"../evil.json": "{}"})
    out_dir = tmp_path / "out"

    with pytest.raises(ZipSafetyError):
        safe_extract_zip(archive, out_dir, ZipLimits())


def test_max_files_limit(tmp_path: Path) -> None:
    archive = tmp_path / "many.zip"
    files = {f"f{i}.json": "{}" for i in range(3)}
    _make_zip(archive, files)
    out_dir = tmp_path / "out_many"

    with pytest.raises(ZipSafetyError):
        safe_extract_zip(archive, out_dir, ZipLimits(max_files=2))


def test_bad_extension_blocked(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    _make_zip(archive, {"run.exe": "x"})
    out_dir = tmp_path / "out_bad"

    with pytest.raises(ZipSafetyError):
        safe_extract_zip(archive, out_dir, ZipLimits())


def test_reset_directory_clears_previous_contents(tmp_path: Path) -> None:
    target = tmp_path / "unpacked"
    nested = target / "old" / "data.json"
    nested.parent.mkdir(parents=True, exist_ok=True)
    nested.write_text("{}", encoding="utf-8")

    reset_directory(target)

    assert target.exists()
    assert list(target.iterdir()) == []
