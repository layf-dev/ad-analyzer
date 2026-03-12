from __future__ import annotations

from pathlib import Path

from jinja2 import Template

from ad_analyzer.explain.templates import HTML_REPORT_TEMPLATE
from ad_analyzer.model.types import Finding


def render_html_report(findings: list[Finding], summary: dict, out_dir: Path) -> Path:
    payload = [f.to_dict() for f in findings]
    template = Template(HTML_REPORT_TEMPLATE)
    html = template.render(findings=payload, summary=summary)
    path = out_dir / "report.html"
    path.write_text(html, encoding="utf-8")
    return path

