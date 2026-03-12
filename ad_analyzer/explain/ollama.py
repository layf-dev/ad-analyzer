from __future__ import annotations

import json
import logging
from dataclasses import asdict
from urllib.error import URLError
from urllib.request import Request, urlopen

from ad_analyzer.config import OllamaConfig
from ad_analyzer.explain.templates import OLLAMA_PROMPT_TEMPLATE
from ad_analyzer.model.types import Finding

logger = logging.getLogger(__name__)


def explain_finding_with_ollama(finding: Finding, cfg: OllamaConfig) -> str | None:
    prompt = OLLAMA_PROMPT_TEMPLATE.format(
        finding_json=json.dumps(asdict(finding), ensure_ascii=False, indent=2, default=str)
    )
    payload = {
        "model": cfg.model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
        },
    }
    data = json.dumps(payload).encode("utf-8")
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
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        logger.warning("Ollama unavailable or failed: %s", exc)
        return None

