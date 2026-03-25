from __future__ import annotations

import json
from urllib.error import URLError

from ad_analyzer.config import OllamaConfig
from ad_analyzer.explain.ollama import (
    check_ollama_health,
    enrich_findings_with_ollama,
    explain_finding_with_ollama,
)
from ad_analyzer.model.types import AffectedObject, Evidence, Severity, create_finding


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _mk_finding() -> object:
    return create_finding(
        title="test finding",
        severity=Severity.HIGH,
        category="ACL",
        affected_objects=[AffectedObject(id="U1", type="USER", name="user1")],
        evidence=Evidence(edges=[{"src_id": "U1", "rel_type": "ACL_RIGHT", "dst_id": "G1"}], path=[], raw_refs=[]),
        why_risky="risk",
        how_to_verify=["verify"],
        fix_plan=["fix"],
    )


def test_ollama_structured_response_is_formatted(monkeypatch) -> None:
    payload = {
        "response": json.dumps(
            {
                "explanation": "Risk explanation",
                "remediation": ["Remove right", "Review delegation"],
            }
        )
    }

    monkeypatch.setattr("ad_analyzer.explain.ollama.urlopen", lambda *args, **kwargs: _FakeResponse(payload))

    finding = _mk_finding()
    text = explain_finding_with_ollama(finding, OllamaConfig())
    assert text is not None
    assert "Пояснение:" in text
    assert "Шаги устранения:" in text
    assert "1. Remove right" in text


def test_ollama_raw_text_fallback(monkeypatch) -> None:
    payload = {"response": "plain text explanation"}
    monkeypatch.setattr("ad_analyzer.explain.ollama.urlopen", lambda *args, **kwargs: _FakeResponse(payload))

    finding = _mk_finding()
    text = explain_finding_with_ollama(finding, OllamaConfig())
    assert text == "plain text explanation"


def test_ollama_health_success(monkeypatch) -> None:
    payload = {"models": [{"name": "llama3.1:8b"}]}
    monkeypatch.setattr("ad_analyzer.explain.ollama.urlopen", lambda *args, **kwargs: _FakeResponse(payload))

    ok, reason = check_ollama_health(OllamaConfig(model="llama3.1:8b"))
    assert ok is True
    assert reason is None


def test_ollama_health_detects_missing_model(monkeypatch) -> None:
    payload = {"models": [{"name": "other-model:latest"}]}
    monkeypatch.setattr("ad_analyzer.explain.ollama.urlopen", lambda *args, **kwargs: _FakeResponse(payload))

    ok, reason = check_ollama_health(OllamaConfig(model="llama3.1:8b"))
    assert ok is False
    assert "not found" in str(reason).lower()


def test_enrich_findings_with_ollama_stops_after_consecutive_failures(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise URLError("timeout")

    monkeypatch.setattr("ad_analyzer.explain.ollama.urlopen", fail)
    findings = [_mk_finding(), _mk_finding(), _mk_finding()]

    success, attempted, stopped_early = enrich_findings_with_ollama(
        findings,
        OllamaConfig(timeout_seconds=1),
        stop_after_consecutive_failures=2,
    )

    assert success == 0
    assert attempted == 2
    assert stopped_early is True


def test_enrich_findings_with_ollama_resets_failure_counter_on_success(monkeypatch) -> None:
    sequence = iter([None, "ok", None, "ok"])

    def fake_explain(*args, **kwargs):
        return next(sequence)

    monkeypatch.setattr("ad_analyzer.explain.ollama.explain_finding_with_ollama", fake_explain)
    findings = [_mk_finding(), _mk_finding(), _mk_finding(), _mk_finding()]

    success, attempted, stopped_early = enrich_findings_with_ollama(
        findings,
        OllamaConfig(timeout_seconds=1),
        stop_after_consecutive_failures=2,
    )

    assert success == 2
    assert attempted == 4
    assert stopped_early is False
