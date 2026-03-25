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
from ad_analyzer.explain.ollama import (
    check_ollama_health,
    enrich_findings_with_ollama,
)
from ad_analyzer.graph.build import build_graph
from ad_analyzer.io.load_json import load_sharphound_jsons
from ad_analyzer.io.strict_input import collect_strict_input_violations
from ad_analyzer.io.zip_safe import ZipSafetyError, reset_directory, safe_extract_zip
from ad_analyzer.model.normalize import normalize_datasets
from ad_analyzer.model.types import Finding, SEVERITY_ORDER, finding_from_dict
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
from ad_analyzer.report.render_json import write_json_reports
from ad_analyzer.report.render_md import render_markdown_report
from ad_analyzer.report.render_pdf import render_pdf_report
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

SEVERITY_LEVEL: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


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
    def _priority_rank(priority: str) -> int:
        value = str(priority).strip().upper()
        if value.startswith("P") and value[1:].isdigit():
            return int(value[1:])
        return 99

    findings.sort(
        key=lambda f: (
            -int(f.risk_score),
            SEVERITY_ORDER.get(f.severity, 99),
            _priority_rank(f.remediation_priority),
            str(f.title).lower(),
            f.id,
        ),
    )
    return findings


def _emit_warnings(
    *,
    load_warnings: list[str],
    normalize_warnings: list[str],
    verbose: bool,
) -> None:
    all_warnings = list(load_warnings) + list(normalize_warnings)
    if not all_warnings:
        return

    if verbose:
        for warning in all_warnings:
            console.print(f"[yellow]Warning:[/yellow] {warning}")
        return

    unknown_json_skipped = sum(1 for w in load_warnings if w.startswith("Unknown JSON file skipped:"))
    invalid_json_skipped = sum(1 for w in load_warnings if w.startswith("Invalid JSON skipped:"))
    no_json_found = any(w.startswith("No JSON files found after extraction.") for w in load_warnings)
    missing_datasets = sorted(
        {
            w.split("'", 2)[1]
            for w in load_warnings
            if w.startswith("Dataset '") and "' not found" in w
        }
    )
    records_skipped_without_id = sum(
        1 for w in normalize_warnings if w.startswith("Skip ") and "without identifier." in w
    )

    parts: list[str] = []
    if unknown_json_skipped:
        parts.append(f"unknown JSON skipped={unknown_json_skipped}")
    if invalid_json_skipped:
        parts.append(f"invalid JSON skipped={invalid_json_skipped}")
    if missing_datasets:
        parts.append(f"missing datasets={','.join(missing_datasets)}")
    if records_skipped_without_id:
        parts.append(f"records skipped without id={records_skipped_without_id}")
    if no_json_found:
        parts.append("no JSON found after extraction")

    if not parts:
        parts.append(f"additional warnings={len(all_warnings)}")
    console.print(
        "[yellow]Warnings:[/yellow] "
        + "; ".join(parts)
        + " (use --verbose for full details)"
    )


def _normalize_severity_filter(value: str) -> str:
    normalized = str(value).strip().upper()
    if normalized in SEVERITY_LEVEL:
        return normalized
    raise typer.BadParameter("Expected one of: LOW, MEDIUM, HIGH, CRITICAL")


def _select_ollama_targets(
    findings: list[Finding],
    *,
    min_severity: str,
    max_findings: int | None,
) -> list[Finding]:
    min_level = SEVERITY_LEVEL[min_severity]
    eligible = [
        f
        for f in findings
        if SEVERITY_LEVEL.get(f.severity.value.upper(), 0) >= min_level
    ]
    if max_findings is None or max_findings <= 0:
        return eligible
    return eligible[:max_findings]


def _apply_ollama_explanations(
    findings: list[Finding],
    *,
    enabled: bool,
    cfg: AnalyzerConfig,
    min_severity: str,
    max_findings: int | None,
    max_consecutive_failures: int,
) -> None:
    if not enabled:
        return
    selected = _select_ollama_targets(
        findings,
        min_severity=min_severity,
        max_findings=max_findings,
    )
    if not selected:
        console.print("[yellow]Ollama skipped:[/yellow] no findings match selected severity/limit.")
        return

    healthy, reason = check_ollama_health(cfg.ollama)
    if not healthy:
        console.print(f"[yellow]Ollama skipped:[/yellow] {reason}")
        return

    console.print(
        f"[cyan]Ollama target findings:[/cyan] {len(selected)} of {len(findings)} "
        f"(min severity: {min_severity})"
    )
    with timed_step("ollama explanations"):
        success, attempted, stopped_early = enrich_findings_with_ollama(
            selected,
            cfg.ollama,
            stop_after_consecutive_failures=max_consecutive_failures,
        )
    if stopped_early:
        console.print(
            "[yellow]Ollama fail-fast:[/yellow] stopped after "
            f"{max_consecutive_failures} consecutive failures."
        )
    console.print(f"[cyan]Ollama explained:[/cyan] {success}/{attempted}")


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
    ollama_host: str | None = typer.Option(
        None, "--ollama-host", help="Ollama host (default: http://127.0.0.1:11434)"
    ),
    ollama_model: str = typer.Option("llama3.1:8b", "--ollama-model"),
    ollama_timeout: int | None = typer.Option(
        None, "--ollama-timeout", help="Ollama request timeout in seconds"
    ),
    ollama_min_severity: str = typer.Option(
        "LOW",
        "--ollama-min-severity",
        help="Minimal finding severity for LLM explanation: LOW|MEDIUM|HIGH|CRITICAL",
        callback=_normalize_severity_filter,
    ),
    ollama_max_findings: int | None = typer.Option(
        None, "--ollama-max-findings", help="Limit number of findings sent to Ollama"
    ),
    ollama_max_consecutive_failures: int = typer.Option(
        3,
        "--ollama-max-consecutive-failures",
        help="Fail-fast for Ollama: stop after N consecutive failed explanations",
    ),
    risk_config: Path | None = typer.Option(
        None, "--risk-config", help="Risk scoring config JSON (weights, thresholds)"
    ),
    allowlist: Path | None = typer.Option(
        None, "--allowlist", help="Allowlist JSON for suppressing known findings"
    ),
    html: bool = typer.Option(False, "--html", help="Generate HTML report"),
    pdf: bool = typer.Option(False, "--pdf", help="Generate PDF report"),
    open_report: bool = typer.Option(
        False, "--open", help="Open generated report (HTML preferred, then PDF)"
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose logs"),
    strict_input: bool = typer.Option(
        False,
        "--strict-input",
        help="Fail analysis on critical input data issues (invalid JSON, missing core datasets, broken records)",
    ),
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
            host=(ollama_host or cfg.ollama.host),
            model=ollama_model,
            timeout_seconds=(
                int(ollama_timeout)
                if ollama_timeout is not None
                else cfg.ollama.timeout_seconds
            ),
        ),
        risk_scoring=risk_scoring_cfg,
    )
    dirs = ensure_output_dirs(out)
    reset_directory(dirs["unpacked"])

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

    with timed_step("normalize data"):
        normalized = normalize_datasets(datasets, warnings=[])

    _emit_warnings(
        load_warnings=load_warnings,
        normalize_warnings=normalized.warnings,
        verbose=verbose,
    )
    if strict_input:
        violations = collect_strict_input_violations(
            load_warnings=load_warnings,
            normalize_warnings=normalized.warnings,
        )
        if violations:
            for warning in violations[:20]:
                console.print(f"[red]Strict input violation:[/red] {warning}")
            if len(violations) > 20:
                console.print(f"[red]... and {len(violations) - 20} more strict violations[/red]")
            raise typer.Exit(
                code=_fatal(
                    "Strict input mode failed: critical data issues detected. "
                    "Fix input/export quality or run without --strict-input."
                )
            )

    with timed_step("build graph + analyze"):
        graph = build_graph(normalized.nodes, normalized.edges)
        findings = run_all_analyzers(graph)
        enrich_findings_with_mitre(findings)
        enrich_findings_with_priority(findings, cfg=cfg.risk_scoring)
        _sort_findings(findings)

    findings, suppressed_count = _maybe_apply_allowlist(findings, allowlist)

    _apply_ollama_explanations(
        findings,
        enabled=ollama,
        cfg=cfg,
        min_severity=ollama_min_severity,
        max_findings=ollama_max_findings,
        max_consecutive_failures=ollama_max_consecutive_failures,
    )

    findings_path, summary_path, summary = write_json_reports(
        findings, dirs["artifacts"], suppressed_count=suppressed_count
    )
    findings_csv = write_findings_csv(findings, dirs["artifacts"])
    report_md = render_markdown_report(findings, summary, dirs["artifacts"])
    report_html: Path | None = None
    report_pdf: Path | None = None
    if html:
        report_html = render_html_report(findings, summary, dirs["artifacts"])
    if pdf:
        report_pdf = render_pdf_report(findings, summary, dirs["artifacts"])

    console.print(f"[green]findings.json:[/green] {findings_path}")
    console.print(f"[green]findings.csv:[/green] {findings_csv}")
    console.print(f"[green]summary.json:[/green] {summary_path}")
    console.print(f"[green]report.md:[/green] {report_md}")
    if report_html:
        console.print(f"[green]report.html:[/green] {report_html}")
    if report_pdf:
        console.print(f"[green]report.pdf:[/green] {report_pdf}")
    _print_summary(summary)

    if open_report:
        if report_html:
            webbrowser.open(report_html.resolve().as_uri())
        elif report_pdf:
            webbrowser.open(report_pdf.resolve().as_uri())
        else:
            console.print(
                "[yellow]--open requested, but no openable report is generated. Use --html and/or --pdf.[/yellow]"
            )


@app.command()
def report(
    dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    ollama: bool = typer.Option(False, "--ollama", help="Enable Ollama explanations"),
    ollama_host: str | None = typer.Option(
        None, "--ollama-host", help="Ollama host (default: http://127.0.0.1:11434)"
    ),
    ollama_model: str = typer.Option("llama3.1:8b", "--ollama-model"),
    ollama_timeout: int | None = typer.Option(
        None, "--ollama-timeout", help="Ollama request timeout in seconds"
    ),
    ollama_min_severity: str = typer.Option(
        "LOW",
        "--ollama-min-severity",
        help="Minimal finding severity for LLM explanation: LOW|MEDIUM|HIGH|CRITICAL",
        callback=_normalize_severity_filter,
    ),
    ollama_max_findings: int | None = typer.Option(
        None, "--ollama-max-findings", help="Limit number of findings sent to Ollama"
    ),
    ollama_max_consecutive_failures: int = typer.Option(
        3,
        "--ollama-max-consecutive-failures",
        help="Fail-fast for Ollama: stop after N consecutive failed explanations",
    ),
    html: bool = typer.Option(False, "--html", help="Generate HTML report"),
    pdf: bool = typer.Option(False, "--pdf", help="Generate PDF report"),
    risk_config: Path | None = typer.Option(
        None, "--risk-config", help="Risk scoring config JSON (weights, thresholds)"
    ),
    allowlist: Path | None = typer.Option(
        None, "--allowlist", help="Allowlist JSON for suppressing known findings"
    ),
    open_report: bool = typer.Option(
        False, "--open", help="Open generated report (HTML preferred, then PDF)"
    ),
) -> None:
    """Regenerate report files from findings.json."""
    _print_banner()
    findings_path = dir / "findings.json"
    if not findings_path.exists():
        raise typer.Exit(code=_fatal(f"findings.json not found in {dir}"))

    try:
        risk_scoring_cfg = load_risk_scoring_config(risk_config)
    except ValueError as exc:
        raise typer.Exit(code=_fatal(f"Invalid risk config: {exc}"))
    cfg = AnalyzerConfig()
    cfg = AnalyzerConfig(
        zip_limits=cfg.zip_limits,
        ollama=cfg.ollama.__class__(
            host=(ollama_host or cfg.ollama.host),
            model=ollama_model,
            timeout_seconds=(
                int(ollama_timeout)
                if ollama_timeout is not None
                else cfg.ollama.timeout_seconds
            ),
        ),
        risk_scoring=risk_scoring_cfg,
    )

    try:
        findings_data = json.loads(findings_path.read_text(encoding="utf-8"))
        if not isinstance(findings_data, list):
            raise ValueError("findings.json must contain a list")
        findings = [finding_from_dict(x) for x in findings_data]
    except (json.JSONDecodeError, ValueError, KeyError, TypeError) as exc:
        raise typer.Exit(code=_fatal(f"Invalid findings.json: {exc}"))
    enrich_findings_with_mitre(findings)
    enrich_findings_with_priority(findings, cfg=cfg.risk_scoring)
    _sort_findings(findings)
    findings, suppressed_count = _maybe_apply_allowlist(findings, allowlist)
    _apply_ollama_explanations(
        findings,
        enabled=ollama,
        cfg=cfg,
        min_severity=ollama_min_severity,
        max_findings=ollama_max_findings,
        max_consecutive_failures=ollama_max_consecutive_failures,
    )

    findings_path, summary_path, summary = write_json_reports(
        findings, dir, suppressed_count=suppressed_count
    )
    findings_csv = write_findings_csv(findings, dir)

    report_md = render_markdown_report(findings, summary, dir)
    console.print(f"[green]findings.json:[/green] {findings_path}")
    console.print(f"[green]summary.json:[/green] {summary_path}")
    console.print(f"[green]findings.csv:[/green] {findings_csv}")
    console.print(f"[green]report.md:[/green] {report_md}")

    report_html: Path | None = None
    report_pdf: Path | None = None
    if html:
        report_html = render_html_report(findings, summary, dir)
        console.print(f"[green]report.html:[/green] {report_html}")
    if pdf:
        report_pdf = render_pdf_report(findings, summary, dir)
        console.print(f"[green]report.pdf:[/green] {report_pdf}")

    if open_report:
        html_candidate = report_html
        if html_candidate is None:
            existing_html = dir / "report.html"
            if existing_html.exists():
                html_candidate = existing_html

        pdf_candidate = report_pdf
        if pdf_candidate is None:
            existing_pdf = dir / "report.pdf"
            if existing_pdf.exists():
                pdf_candidate = existing_pdf

        if html_candidate:
            webbrowser.open(html_candidate.resolve().as_uri())
        elif pdf_candidate:
            webbrowser.open(pdf_candidate.resolve().as_uri())
        else:
            console.print(
                "[yellow]--open requested, but no openable report exists. Generate with --html and/or --pdf.[/yellow]"
            )

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

    try:
        old_findings = load_findings_file(old_path)
        new_findings = load_findings_file(new_path)
    except (json.JSONDecodeError, ValueError, KeyError, TypeError) as exc:
        raise typer.Exit(code=_fatal(f"Invalid findings file: {exc}"))
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
