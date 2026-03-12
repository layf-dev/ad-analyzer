from __future__ import annotations

import json
import logging
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ad_analyzer import __version__
from ad_analyzer.analyzers import run_all_analyzers
from ad_analyzer.config import AnalyzerConfig, load_risk_scoring_config, ensure_output_dirs
from ad_analyzer.explain.ollama import explain_finding_with_ollama
from ad_analyzer.graph.build import build_graph
from ad_analyzer.io.load_json import load_sharphound_jsons
from ad_analyzer.io.zip_safe import ZipSafetyError, safe_extract_zip
from ad_analyzer.model.normalize import normalize_datasets
from ad_analyzer.model.types import Finding, finding_from_dict
from ad_analyzer.report.allowlist import apply_allowlist, load_allowlist
from ad_analyzer.report.diff import (
    compare_findings,
    load_findings_file,
    render_diff_markdown,
    write_diff_json,
)
from ad_analyzer.report.mitre import enrich_findings_with_mitre
from ad_analyzer.report.prioritize import enrich_findings_with_priority
from ad_analyzer.report.render_csv import write_findings_csv
from ad_analyzer.report.render_html import render_html_report
from ad_analyzer.report.render_json import build_summary, write_json_reports
from ad_analyzer.report.render_md import render_markdown_report
from ad_analyzer.utils.logging import setup_logging
from ad_analyzer.utils.timeit import timed_step

app = typer.Typer(help="AD Analyzer: Blue Team extension for SharpHound/BloodHound data")
console = Console()
logger = logging.getLogger(__name__)

BANNER = r"""
    ___    ____      ___                __
   /   |  / __ \    /   |  ____  ____ _/ /_  ______  ___  _____
  / /| | / / / /   / /| | / __ \/ __ `/ / / / / __ \/ _ \/ ___/
 / ___ |/ /_/ /   / ___ |/ / / / /_/ / / /_/ / /_/ /  __/ /
/_/  |_/_____/   /_/  |_/_/ /_/\__,_/_/\__, /\____/\___/_/
                                       /____/
"""


def _print_summary(summary: dict) -> None:
    table = Table(title="Findings Summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        table.add_row(severity, str(summary["by_severity"][severity]))
    table.add_row("TOTAL", str(summary["total"]))
    table.add_row("SUPPRESSED", str(summary.get("suppressed", 0)))
    table.add_row("AVG_RISK", str(summary.get("avg_risk_score", 0)))
    table.add_row("P1", str(summary.get("by_priority", {}).get("P1", 0)))
    table.add_row("P2", str(summary.get("by_priority", {}).get("P2", 0)))
    table.add_row("P3", str(summary.get("by_priority", {}).get("P3", 0)))
    table.add_row("P4", str(summary.get("by_priority", {}).get("P4", 0)))
    console.print(table)


def _print_banner() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]{BANNER}[/bold cyan]\n[bold]Blue Team AD Analyzer[/bold]",
            title="AD Analyzer",
            border_style="cyan",
        )
    )


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    findings.sort(
        key=lambda f: (
            f.risk_score,
            f.severity.value,
            f.remediation_priority,
            f.title,
        ),
        reverse=True,
    )
    return findings


def _resolve_findings_path(path: Path) -> Path:
    if path.is_dir():
        candidate = path / "findings.json"
        if candidate.exists():
            return candidate
    if path.is_file() and path.suffix.lower() == ".json":
        return path
    raise FileNotFoundError(f"Unable to resolve findings.json from: {path}")


def _maybe_apply_allowlist(
    findings: list[Finding], allowlist_path: Path | None
) -> tuple[list[Finding], int]:
    if not allowlist_path:
        return findings, 0
    try:
        allowlist_data = load_allowlist(allowlist_path)
    except (ValueError, json.JSONDecodeError) as exc:
        raise typer.Exit(code=_fatal(f"Invalid allowlist file: {exc}"))
    result = apply_allowlist(findings, allowlist_data)
    console.print(f"[cyan]Allowlist suppressed:[/cyan] {len(result.suppressed)}")
    return result.findings, len(result.suppressed)


@app.command()
def analyze(
    path_to_sharphound_zip: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(..., "--out", help="Output directory"),
    ollama: bool = typer.Option(False, "--ollama", help="Enable Ollama explanations"),
    ollama_model: str = typer.Option("llama3.1:8b", "--ollama-model"),
    risk_config: Path | None = typer.Option(
        None, "--risk-config", help="Risk scoring config JSON (weights, thresholds)"
    ),
    allowlist: Path | None = typer.Option(
        None, "--allowlist", help="Allowlist JSON for suppressing known findings"
    ),
    html: bool = typer.Option(False, "--html", help="Generate HTML report"),
    open_report: bool = typer.Option(False, "--open", help="Open generated HTML report"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose logs"),
) -> None:
    """Analyze SharpHound ZIP and produce findings/report artifacts."""
    _print_banner()
    setup_logging(verbose)
    cfg = AnalyzerConfig()
    try:
        risk_scoring_cfg = load_risk_scoring_config(risk_config)
    except ValueError as exc:
        raise typer.Exit(code=_fatal(f"Invalid risk config: {exc}"))
    cfg = AnalyzerConfig(
        zip_limits=cfg.zip_limits,
        ollama=cfg.ollama.__class__(
            host=cfg.ollama.host,
            model=ollama_model,
            timeout_seconds=cfg.ollama.timeout_seconds,
        ),
        risk_scoring=risk_scoring_cfg,
    )
    dirs = ensure_output_dirs(out)

    try:
        with timed_step("safe zip extraction"):
            extraction = safe_extract_zip(path_to_sharphound_zip, dirs["unpacked"], cfg.zip_limits)
            logger.info(
                "Extracted %d files, total unpacked bytes=%d",
                len(extraction.extracted_files),
                extraction.total_unpacked_bytes,
            )
    except ZipSafetyError as exc:
        raise typer.Exit(code=_fatal(f"ZIP validation failed: {exc}"))

    with timed_step("load json datasets"):
        datasets, load_warnings = load_sharphound_jsons(dirs["unpacked"])
        for warning in load_warnings:
            console.print(f"[yellow]Warning:[/yellow] {warning}")

    with timed_step("normalize data"):
        normalized = normalize_datasets(datasets, warnings=load_warnings)
        for warning in normalized.warnings:
            logger.warning(warning)

    with timed_step("build graph + analyze"):
        graph = build_graph(normalized.nodes, normalized.edges)
        findings = run_all_analyzers(graph)
        enrich_findings_with_mitre(findings)
        enrich_findings_with_priority(findings, cfg=cfg.risk_scoring)
        _sort_findings(findings)

    findings, suppressed_count = _maybe_apply_allowlist(findings, allowlist)

    if ollama:
        with timed_step("ollama explanations"):
            for finding in findings:
                explanation = explain_finding_with_ollama(finding, cfg.ollama)
                if explanation:
                    finding.llm_explanation = explanation

    findings_path, summary_path, summary = write_json_reports(
        findings, dirs["artifacts"], suppressed_count=suppressed_count
    )
    findings_csv = write_findings_csv(findings, dirs["artifacts"])
    report_md = render_markdown_report(findings, summary, dirs["artifacts"])
    report_html: Path | None = None
    if html:
        report_html = render_html_report(findings, summary, dirs["artifacts"])

    console.print(f"[green]findings.json:[/green] {findings_path}")
    console.print(f"[green]findings.csv:[/green] {findings_csv}")
    console.print(f"[green]summary.json:[/green] {summary_path}")
    console.print(f"[green]report.md:[/green] {report_md}")
    if report_html:
        console.print(f"[green]report.html:[/green] {report_html}")
    _print_summary(summary)

    if open_report:
        if report_html:
            webbrowser.open(report_html.resolve().as_uri())
        else:
            console.print("[yellow]--open requested, but HTML report is not generated. Use --html.[/yellow]")


@app.command()
def report(
    dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    html: bool = typer.Option(False, "--html", help="Generate HTML report"),
    risk_config: Path | None = typer.Option(
        None, "--risk-config", help="Risk scoring config JSON (weights, thresholds)"
    ),
    allowlist: Path | None = typer.Option(
        None, "--allowlist", help="Allowlist JSON for suppressing known findings"
    ),
    open_report: bool = typer.Option(False, "--open", help="Open HTML report"),
) -> None:
    """Regenerate report files from findings.json."""
    _print_banner()
    findings_path = dir / "findings.json"
    summary_path = dir / "summary.json"
    if not findings_path.exists():
        raise typer.Exit(code=_fatal(f"findings.json not found in {dir}"))

    try:
        risk_scoring_cfg = load_risk_scoring_config(risk_config)
    except ValueError as exc:
        raise typer.Exit(code=_fatal(f"Invalid risk config: {exc}"))

    findings_data = json.loads(findings_path.read_text(encoding="utf-8"))
    findings = [finding_from_dict(x) for x in findings_data]
    enrich_findings_with_mitre(findings)
    enrich_findings_with_priority(findings, cfg=risk_scoring_cfg)
    _sort_findings(findings)
    findings, suppressed_count = _maybe_apply_allowlist(findings, allowlist)

    summary = build_summary(findings, suppressed_count=suppressed_count)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    findings_csv = write_findings_csv(findings, dir)

    report_md = render_markdown_report(findings, summary, dir)
    console.print(f"[green]findings.csv:[/green] {findings_csv}")
    console.print(f"[green]report.md:[/green] {report_md}")

    report_html: Path | None = None
    if html:
        report_html = render_html_report(findings, summary, dir)
        console.print(f"[green]report.html:[/green] {report_html}")

    if open_report and report_html:
        webbrowser.open(report_html.resolve().as_uri())
    elif open_report:
        console.print("[yellow]--open requested, but HTML report is not generated. Use --html.[/yellow]")

    _print_summary(summary)


@app.command()
def diff(
    old: Path = typer.Argument(..., exists=True, help="Old findings dir or findings.json"),
    new: Path = typer.Argument(..., exists=True, help="New findings dir or findings.json"),
    out: Path | None = typer.Option(None, "--out", help="Output directory for diff files"),
) -> None:
    """Compare two runs and show new/resolved/persistent findings."""
    _print_banner()
    try:
        old_path = _resolve_findings_path(old)
        new_path = _resolve_findings_path(new)
    except FileNotFoundError as exc:
        raise typer.Exit(code=_fatal(str(exc)))

    old_findings = load_findings_file(old_path)
    new_findings = load_findings_file(new_path)
    diff_result = compare_findings(old_findings, new_findings)

    out_dir = out or new_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    diff_json = write_diff_json(diff_result, out_dir / "diff.json")
    diff_md = render_diff_markdown(diff_result, out_dir / "diff.md")

    summary = diff_result.to_dict()["summary"]
    console.print(f"[green]diff.json:[/green] {diff_json}")
    console.print(f"[green]diff.md:[/green] {diff_md}")
    console.print(
        f"New={summary['new_count']} | Resolved={summary['resolved_count']} | "
        f"Persistent={summary['persistent_count']} | SeverityChanged={summary['severity_changed_count']}"
    )


@app.command()
def version() -> None:
    """Show current version."""
    _print_banner()
    console.print(__version__)


def _fatal(message: str) -> int:
    console.print(f"[red]{message}[/red]")
    return 1
