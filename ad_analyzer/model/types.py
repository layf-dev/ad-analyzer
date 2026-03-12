from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any
from uuid import NAMESPACE_URL, uuid5


class NodeType(str, Enum):
    USER = "USER"
    GROUP = "GROUP"
    COMPUTER = "COMPUTER"
    DOMAIN = "DOMAIN"
    OTHER = "OTHER"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


@dataclass(slots=True)
class Node:
    id: str
    type: NodeType
    name: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Edge:
    src_id: str
    rel_type: str
    dst_id: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AffectedObject:
    id: str
    type: str
    name: str


@dataclass(slots=True)
class Evidence:
    edges: list[dict[str, Any]] = field(default_factory=list)
    path: list[str] = field(default_factory=list)
    raw_refs: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MitreAttackRef:
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    affected_objects: list[AffectedObject]
    evidence: Evidence
    why_risky: str
    how_to_verify: list[str]
    fix_plan: list[str]
    mitre_attack: list[MitreAttackRef] = field(default_factory=list)
    risk_score: int = 0
    remediation_priority: str = "P4"
    notes: str | None = None
    llm_explanation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


_WHITESPACE_RE = re.compile(r"\s+")


def _norm_text(value: str) -> str:
    return _WHITESPACE_RE.sub(" ", value.strip().lower())


def _normalize_edge_for_fingerprint(edge: dict[str, Any]) -> dict[str, Any]:
    rights: list[str] = []
    raw_rights = edge.get("rights")
    if isinstance(raw_rights, list):
        rights = sorted(_norm_text(str(x)) for x in raw_rights if str(x).strip())
    elif edge.get("right"):
        rights = [_norm_text(str(edge["right"]))]
    return {
        "src_id": str(edge.get("src_id", "")).strip(),
        "rel_type": _norm_text(str(edge.get("rel_type", ""))),
        "dst_id": str(edge.get("dst_id", "")).strip(),
        "rights": rights,
    }


def finding_signature_payload(
    *,
    category: str,
    title: str,
    affected_objects: list[AffectedObject],
    evidence: Evidence,
) -> dict[str, Any]:
    normalized_edges = sorted(
        (_normalize_edge_for_fingerprint(edge) for edge in evidence.edges),
        key=lambda x: (x["src_id"], x["rel_type"], x["dst_id"], ",".join(x["rights"])),
    )
    payload = {
        "category": _norm_text(category),
        "title": _norm_text(title),
        "affected_ids": sorted(str(obj.id).strip() for obj in affected_objects),
        "path": [str(x).strip() for x in evidence.path],
        "edges": normalized_edges,
    }
    return payload


def finding_fingerprint(
    *,
    category: str,
    title: str,
    affected_objects: list[AffectedObject],
    evidence: Evidence,
) -> str:
    payload = finding_signature_payload(
        category=category,
        title=title,
        affected_objects=affected_objects,
        evidence=evidence,
    )
    raw = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_stable_finding_id(
    *,
    category: str,
    title: str,
    affected_objects: list[AffectedObject],
    evidence: Evidence,
) -> str:
    fingerprint = finding_fingerprint(
        category=category,
        title=title,
        affected_objects=affected_objects,
        evidence=evidence,
    )
    return str(uuid5(NAMESPACE_URL, fingerprint))


def finding_from_dict(data: dict[str, Any]) -> Finding:
    return Finding(
        id=data["id"],
        title=data["title"],
        severity=Severity(data["severity"]),
        category=data["category"],
        affected_objects=[AffectedObject(**x) for x in data.get("affected_objects", [])],
        evidence=Evidence(**data.get("evidence", {})),
        why_risky=data.get("why_risky", ""),
        how_to_verify=data.get("how_to_verify", []),
        fix_plan=data.get("fix_plan", []),
        mitre_attack=[MitreAttackRef(**x) for x in data.get("mitre_attack", [])],
        risk_score=int(data.get("risk_score", 0)),
        remediation_priority=str(data.get("remediation_priority", "P4")),
        notes=data.get("notes"),
        llm_explanation=data.get("llm_explanation"),
    )


def create_finding(
    *,
    title: str,
    severity: Severity,
    category: str,
    affected_objects: list[AffectedObject],
    evidence: Evidence,
    why_risky: str,
    how_to_verify: list[str],
    fix_plan: list[str],
    mitre_attack: list[MitreAttackRef] | None = None,
    risk_score: int = 0,
    remediation_priority: str = "P4",
    notes: str | None = None,
) -> Finding:
    return Finding(
        id=build_stable_finding_id(
            category=category,
            title=title,
            affected_objects=affected_objects,
            evidence=evidence,
        ),
        title=title,
        severity=severity,
        category=category,
        affected_objects=affected_objects,
        evidence=evidence,
        why_risky=why_risky,
        how_to_verify=how_to_verify,
        fix_plan=fix_plan,
        mitre_attack=list(mitre_attack or []),
        risk_score=risk_score,
        remediation_priority=remediation_priority,
        notes=notes,
    )
