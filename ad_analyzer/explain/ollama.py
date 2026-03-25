from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ad_analyzer.config import OllamaConfig
from ad_analyzer.explain.templates import OLLAMA_PROMPT_TEMPLATE
from ad_analyzer.model.types import Finding

logger = logging.getLogger(__name__)


def _finding_context_for_llm(finding: Finding) -> dict:
    context = asdict(finding)
    context.pop("llm_explanation", None)
    evidence = context.get("evidence", {})
    edges = evidence.get("edges", [])
    max_edges = 8
    if isinstance(edges, list) and len(edges) > max_edges:
        evidence["edges"] = edges[:max_edges]
        evidence["edges_truncated"] = len(edges) - max_edges
    return context


def _extract_json_obj(text: str) -> dict | None:
    stripped = text.strip()
    for candidate in (
        stripped,
        stripped.strip("`"),
    ):
        try:
            decoded = json.loads(candidate)
            if isinstance(decoded, dict):
                return decoded
        except json.JSONDecodeError:
            pass

    match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
    if not match:
        return None
    try:
        decoded = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, dict) else None


def _format_structured_explanation(payload: dict) -> str | None:
    explanation = str(payload.get("explanation", "")).strip()
    remediation_raw = payload.get("remediation")
    remediation: list[str] = []
    if isinstance(remediation_raw, list):
        remediation = [str(x).strip() for x in remediation_raw if str(x).strip()]
    elif isinstance(remediation_raw, str) and remediation_raw.strip():
        remediation = [remediation_raw.strip()]
    if not explanation and not remediation:
        return None
    lines: list[str] = []
    if explanation:
        lines.extend(["Пояснение:", explanation, ""])
    if remediation:
        lines.append("Шаги устранения:")
        for idx, step in enumerate(remediation, start=1):
            lines.append(f"{idx}. {step}")
    return "\n".join(lines).strip() or None


def _ollama_post_generate(prompt: str, cfg: OllamaConfig, retries: int = 1) -> str | None:
    payload = {
        "model": cfg.model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
        },
    }
    data = json.dumps(payload).encode("utf-8")
    last_exc: Exception | None = None
    for _ in range(retries + 1):
        req = Request(
            url=f"{cfg.host.rstrip('/')}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=cfg.timeout_seconds) as response:
                body = response.read().decode("utf-8")
                decoded = json.loads(body)
                text = str(decoded.get("response", "")).strip()
                return text or None
        except (URLError, TimeoutError, OSError, json.JSONDecodeError, HTTPError) as exc:
            last_exc = exc
    logger.debug("Ollama unavailable or failed: %s", last_exc)
    return None


def check_ollama_health(cfg: OllamaConfig) -> tuple[bool, str | None]:
    req = Request(
        url=f"{cfg.host.rstrip('/')}/api/tags",
        method="GET",
    )
    try:
        with urlopen(req, timeout=cfg.timeout_seconds) as response:
            body = response.read().decode("utf-8")
            decoded = json.loads(body)
            models = decoded.get("models")
            if isinstance(models, list):
                names = {str(row.get("name", "")).strip() for row in models if isinstance(row, dict)}
                if names and cfg.model not in names:
                    return (
                        False,
                        f"Model '{cfg.model}' not found in local Ollama. Pull it first: ollama pull {cfg.model}",
                    )
            return True, None
    except (URLError, TimeoutError, OSError, json.JSONDecodeError, HTTPError) as exc:
        return False, str(exc)


def explain_finding_with_ollama(finding: Finding, cfg: OllamaConfig) -> str | None:
    prompt = OLLAMA_PROMPT_TEMPLATE.format(
        finding_json=json.dumps(_finding_context_for_llm(finding), ensure_ascii=False, indent=2)
    )
    text = _ollama_post_generate(prompt=prompt, cfg=cfg, retries=1)
    if not text:
        return None
    parsed = _extract_json_obj(text)
    if not parsed:
        return text
    formatted = _format_structured_explanation(parsed)
    return formatted or text


def enrich_findings_with_ollama(
    findings: list[Finding],
    cfg: OllamaConfig,
    *,
    stop_after_consecutive_failures: int = 3,
) -> tuple[int, int, bool]:
    success = 0
    attempted = 0
    consecutive_failures = 0
    stopped_early = False

    for finding in findings:
        attempted += 1
        explanation = explain_finding_with_ollama(finding, cfg)
        if explanation:
            finding.llm_explanation = explanation
            success += 1
            consecutive_failures = 0
            continue

        consecutive_failures += 1
        if stop_after_consecutive_failures > 0 and consecutive_failures >= stop_after_consecutive_failures:
            stopped_early = True
            break

    return success, attempted, stopped_early
