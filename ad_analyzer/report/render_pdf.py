from __future__ import annotations

import json
import logging
import platform
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen.canvas import Canvas

    _REPORTLAB_AVAILABLE = True
except ModuleNotFoundError:
    A4 = (595.2755905511812, 841.8897637795277)  # points
    pdfmetrics = None
    TTFont = None
    Canvas = None
    _REPORTLAB_AVAILABLE = False

from ad_analyzer.model.types import Finding


logger = logging.getLogger(__name__)
PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 36
CONTENT_WIDTH = PAGE_WIDTH - (MARGIN * 2)


def _font_candidates() -> list[Path]:
    system = platform.system().lower()
    candidates: list[Path] = []
    if system == "windows":
        win = Path("C:/Windows/Fonts")
        candidates.extend([win / "arial.ttf", win / "segoeui.ttf"])
    elif system == "darwin":
        candidates.extend(
            [
                Path("/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
                Path("/Library/Fonts/Arial Unicode.ttf"),
                Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
            ]
        )
    else:
        candidates.extend(
            [
                Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
                Path("/usr/share/fonts/TTF/DejaVuSans.ttf"),
                Path("/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf"),
            ]
        )
    return candidates


def _resolve_font() -> tuple[str, bool]:
    if not _REPORTLAB_AVAILABLE:
        return "Helvetica", False
    for path in _font_candidates():
        if not path.exists():
            continue
        pdfmetrics.registerFont(TTFont("ADAnalyzerUnicode", str(path)))
        return "ADAnalyzerUnicode", True
    return "Helvetica", False


def _safe_text(text: str, unicode_ok: bool) -> str:
    if unicode_ok:
        return text
    return text.encode("latin-1", errors="replace").decode("latin-1")


class _Writer:
    def __init__(self, canvas: Canvas, font_name: str, unicode_ok: bool) -> None:
        self.canvas = canvas
        self.font_name = font_name
        self.unicode_ok = unicode_ok
        self.y = PAGE_HEIGHT - MARGIN

    def _new_page(self) -> None:
        self.canvas.showPage()
        self.y = PAGE_HEIGHT - MARGIN

    def _ensure_space(self, font_size: int, line_count: int = 1) -> None:
        needed = font_size * 1.35 * line_count
        if self.y - needed < MARGIN:
            self._new_page()

    def _string_width(self, text: str, font_size: int) -> float:
        return pdfmetrics.stringWidth(text, self.font_name, font_size)

    def _fit_text(self, text: str, font_size: int, max_width: float) -> list[str]:
        normalized = " ".join(text.strip().split())
        if not normalized:
            return [""]
        words = normalized.split(" ")

        def _split_long_token(token: str) -> list[str]:
            if self._string_width(token, font_size) <= max_width:
                return [token]
            chunks: list[str] = []
            current_chunk = ""
            for ch in token:
                candidate = f"{current_chunk}{ch}"
                if current_chunk and self._string_width(candidate, font_size) > max_width:
                    chunks.append(current_chunk)
                    current_chunk = ch
                else:
                    current_chunk = candidate
            if current_chunk:
                chunks.append(current_chunk)
            return chunks

        prepared_words: list[str] = []
        for word in words:
            prepared_words.extend(_split_long_token(word))

        lines: list[str] = []
        current = prepared_words[0]
        for word in prepared_words[1:]:
            candidate = f"{current} {word}"
            if self._string_width(candidate, font_size) <= max_width:
                current = candidate
                continue
            lines.append(current)
            current = word
        lines.append(current)
        return lines

    def write_wrapped(
        self,
        text: str,
        *,
        font_size: int = 10,
        indent: int = 0,
        prefix: str = "",
    ) -> None:
        if not text:
            self.write_line("", font_size=font_size, indent=indent)
            return

        safe_prefix = _safe_text(prefix, self.unicode_ok)
        continuation_prefix = " " * len(prefix)
        safe_continuation_prefix = _safe_text(continuation_prefix, self.unicode_ok)
        max_width = CONTENT_WIDTH - indent

        paragraphs = text.splitlines() or [text]
        for paragraph in paragraphs:
            line_prefix = safe_prefix
            if paragraph.strip() == "":
                self.write_line("", font_size=font_size, indent=indent)
                continue

            available_width = max(20, max_width - self._string_width(line_prefix, font_size))
            wrapped = self._fit_text(_safe_text(paragraph, self.unicode_ok), font_size, available_width)
            for idx, part in enumerate(wrapped):
                pref = line_prefix if idx == 0 else safe_continuation_prefix
                self.write_line(f"{pref}{part}", font_size=font_size, indent=indent)
            safe_prefix = safe_continuation_prefix

    def write_line(self, text: str, *, font_size: int = 10, indent: int = 0) -> None:
        self._ensure_space(font_size)
        self.canvas.setFont(self.font_name, font_size)
        self.canvas.drawString(MARGIN + indent, self.y, _safe_text(text, self.unicode_ok))
        self.y -= font_size * 1.35

    def spacer(self, lines: int = 1, font_size: int = 10) -> None:
        self._ensure_space(font_size, line_count=lines)
        self.y -= font_size * 1.35 * lines


def _finding_lines(finding: Finding) -> tuple[list[str], list[str], list[str]]:
    affected = [f"- {obj.type}:{obj.name} ({obj.id})" for obj in finding.affected_objects] or ["- n/a"]
    mitre = (
        [
            f"- {m.tactic_id}/{m.technique_id}: {m.technique_name}"
            for m in finding.mitre_attack
        ]
        or ["- n/a"]
    )
    path = " -> ".join(finding.evidence.path) if finding.evidence.path else "n/a"
    evidence = [
        f"path: {path}",
        f"raw_refs: {', '.join(finding.evidence.raw_refs) if finding.evidence.raw_refs else 'n/a'}",
    ]
    if finding.evidence.edges:
        evidence.append(f"edges: {json.dumps(finding.evidence.edges, ensure_ascii=False)}")
    return affected, mitre, evidence


def _pdf_escape(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _build_minimal_pdf(lines: list[str]) -> bytes:
    content_lines = ["BT", "/F1 10 Tf", "40 800 Td"]
    for idx, line in enumerate(lines):
        if idx > 0:
            content_lines.append("0 -13 Td")
        content_lines.append(f"({_pdf_escape(line)}) Tj")
    content_lines.append("ET")
    content_stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content_stream), content_stream),
    ]

    payload = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(payload))
        payload.extend(f"{index} 0 obj\n".encode("ascii"))
        payload.extend(obj)
        payload.extend(b"\nendobj\n")

    xref_pos = len(payload)
    payload.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    payload.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        payload.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    payload.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(payload)


def _fallback_render_pdf(findings: list[Finding], summary: dict, out_path: Path) -> None:
    lines = [
        "Отчет AD Analyzer (fallback-рендерер)",
        f"Сгенерировано: {datetime.now().isoformat(timespec='seconds')}",
        "",
        f"Всего находок: {summary.get('total', 0)}",
        f"Подавлено: {summary.get('suppressed', 0)}",
    ]
    by_sev = summary.get("by_severity", {})
    lines.extend(
        [
            f"CRITICAL: {by_sev.get('CRITICAL', 0)}",
            f"HIGH: {by_sev.get('HIGH', 0)}",
            f"MEDIUM: {by_sev.get('MEDIUM', 0)}",
            f"LOW: {by_sev.get('LOW', 0)}",
            "",
            "Находки:",
        ]
    )
    for index, finding in enumerate(findings, start=1):
        lines.append(
            f"[{index}] {finding.severity.value} {finding.category}: {finding.title}"
        )
    out_path.write_bytes(_build_minimal_pdf(lines))


def render_pdf_report(findings: list[Finding], summary: dict, out_dir: Path) -> Path:
    out_path = out_dir / "report.pdf"
    if not _REPORTLAB_AVAILABLE:
        logger.warning(
            "reportlab не установлен; используется минимальный fallback-рендерер PDF"
        )
        _fallback_render_pdf(findings, summary, out_path)
        return out_path

    canvas = Canvas(str(out_path), pagesize=A4)
    font_name, unicode_ok = _resolve_font()
    w = _Writer(canvas, font_name, unicode_ok)

    w.write_line("Отчёт AD Analyzer", font_size=16)
    w.write_line(f"Сгенерировано: {datetime.now().isoformat(timespec='seconds')}", font_size=9)
    w.spacer()

    w.write_line("Сводка", font_size=13)
    w.write_wrapped(f"Всего находок: {summary.get('total', 0)}", font_size=10, prefix="- ")
    w.write_wrapped(
        f"Подавлено allowlist: {summary.get('suppressed', 0)}",
        font_size=10,
        prefix="- ",
    )
    by_sev = summary.get("by_severity", {})
    w.write_wrapped(f"CRITICAL: {by_sev.get('CRITICAL', 0)}", font_size=10, prefix="- ")
    w.write_wrapped(f"HIGH: {by_sev.get('HIGH', 0)}", font_size=10, prefix="- ")
    w.write_wrapped(f"MEDIUM: {by_sev.get('MEDIUM', 0)}", font_size=10, prefix="- ")
    w.write_wrapped(f"LOW: {by_sev.get('LOW', 0)}", font_size=10, prefix="- ")
    by_priority = summary.get("by_priority", {})
    w.write_wrapped(
        (
            "Priority: "
            f"P1={by_priority.get('P1', 0)}, "
            f"P2={by_priority.get('P2', 0)}, "
            f"P3={by_priority.get('P3', 0)}, "
            f"P4={by_priority.get('P4', 0)}"
        ),
        font_size=10,
        prefix="- ",
    )
    w.write_wrapped(
        f"Средний risk score: {summary.get('avg_risk_score', 0)}", font_size=10, prefix="- "
    )
    w.spacer(lines=2)

    w.write_line("Находки", font_size=13)
    w.spacer()

    for index, finding in enumerate(findings, start=1):
        affected, mitre, evidence = _finding_lines(finding)
        w.write_wrapped(f"[{index}] {finding.title}", font_size=12)
        w.write_wrapped(f"ID: {finding.id}", font_size=9, prefix="- ")
        w.write_wrapped(
            (
                "Severity/Risk/Priority: "
                f"{finding.severity.value} / {finding.risk_score} / {finding.remediation_priority}"
            ),
            font_size=9,
            prefix="- ",
        )
        w.write_wrapped(f"Категория: {finding.category}", font_size=9, prefix="- ")

        w.write_wrapped("Затронутые объекты:", font_size=10, prefix="- ")
        for line in affected:
            w.write_wrapped(line, font_size=9, indent=14)

        w.write_wrapped("MITRE ATT&CK:", font_size=10, prefix="- ")
        for line in mitre:
            w.write_wrapped(line, font_size=9, indent=14)

        w.write_wrapped("Доказательства:", font_size=10, prefix="- ")
        for line in evidence:
            w.write_wrapped(f"- {line}", font_size=9, indent=14)

        w.write_wrapped("Почему это риск:", font_size=10, prefix="- ")
        w.write_wrapped(finding.why_risky, font_size=9, indent=14)

        w.write_wrapped("Как проверить:", font_size=10, prefix="- ")
        for item in finding.how_to_verify or ["n/a"]:
            w.write_wrapped(f"- {item}", font_size=9, indent=14)

        w.write_wrapped("План исправления:", font_size=10, prefix="- ")
        for num, item in enumerate(finding.fix_plan or ["n/a"], start=1):
            w.write_wrapped(f"{num}. {item}", font_size=9, indent=14)

        if finding.notes:
            w.write_wrapped("Примечания:", font_size=10, prefix="- ")
            w.write_wrapped(finding.notes, font_size=9, indent=14)
        if finding.llm_explanation:
            w.write_wrapped("Пояснение LLM:", font_size=10, prefix="- ")
            w.write_wrapped(finding.llm_explanation, font_size=9, indent=14)

        if index != len(findings):
            w.spacer(lines=2)

    canvas.save()
    return out_path
