from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from zipfile import ZipFile

from ad_analyzer.config import ZipLimits


class ZipSafetyError(RuntimeError):
    pass


@dataclass(slots=True)
class ZipExtractionResult:
    extracted_files: list[Path]
    total_unpacked_bytes: int


def reset_directory(path: Path) -> None:
    """Drop directory contents to guarantee reproducible extraction output."""
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _is_safe_destination(base_dir: Path, target_path: Path) -> bool:
    base = base_dir.resolve()
    target = target_path.resolve()
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def safe_extract_zip(zip_path: Path, out_dir: Path, limits: ZipLimits) -> ZipExtractionResult:
    if not zip_path.exists():
        raise ZipSafetyError(f"Archive not found: {zip_path}")

    archive_size = zip_path.stat().st_size
    if archive_size > limits.max_archive_size_bytes:
        raise ZipSafetyError(
            f"Archive too large: {archive_size} bytes > {limits.max_archive_size_bytes} bytes"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    total_unpacked = 0

    with ZipFile(zip_path, "r") as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > limits.max_files:
            raise ZipSafetyError(f"Too many files in archive: {len(infos)} > {limits.max_files}")

        for info in infos:
            filename = Path(info.filename)
            ext = filename.suffix.lower()
            if ext not in limits.allowed_extensions:
                raise ZipSafetyError(
                    f"Unsupported file extension in archive: {filename.name} ({ext})"
                )

            target = out_dir / filename
            if not _is_safe_destination(out_dir, target):
                raise ZipSafetyError(f"Blocked zip-slip path: {info.filename}")

            total_unpacked += info.file_size
            if total_unpacked > limits.max_unpacked_size_bytes:
                raise ZipSafetyError(
                    "Total unpacked size exceeds limit: "
                    f"{total_unpacked} > {limits.max_unpacked_size_bytes} bytes"
                )

        for info in infos:
            target = out_dir / Path(info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted.append(target)

    return ZipExtractionResult(extracted_files=extracted, total_unpacked_bytes=total_unpacked)
