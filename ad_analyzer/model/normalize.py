from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ad_analyzer.model.types import Edge, Node, NodeType


NODE_DATASETS: dict[str, NodeType] = {
    "users": NodeType.USER,
    "groups": NodeType.GROUP,
    "computers": NodeType.COMPUTER,
    "domains": NodeType.DOMAIN,
}


@dataclass(slots=True)
class NormalizedData:
    nodes: list[Node]
    edges: list[Edge]
    warnings: list[str] = field(default_factory=list)


def _ci_get(data: dict[str, Any], key: str, default: Any = None) -> Any:
    if key in data:
        return data[key]
    key_l = key.lower()
    for k, v in data.items():
        if k.lower() == key_l:
            return v
    return default


def _extract_identifier(record: dict[str, Any]) -> str | None:
    candidates = [
        "ObjectIdentifier",
        "objectIdentifier",
        "ObjectId",
        "objectId",
        "SID",
        "sid",
        "Guid",
        "GUID",
        "id",
    ]
    for key in candidates:
        value = _ci_get(record, key)
        if value:
            return str(value)
    props = _ci_get(record, "Properties", {})
    if isinstance(props, dict):
        for key in ("objectid", "objectsid", "sid", "guid"):
            value = _ci_get(props, key)
            if value:
                return str(value)
    return None


def _extract_name(record: dict[str, Any], fallback_id: str) -> str:
    props = _ci_get(record, "Properties", {})
    if isinstance(props, dict):
        for key in ("name", "samaccountname", "displayname"):
            value = _ci_get(props, key)
            if value:
                return str(value)
    for key in ("Name", "name", "DisplayName"):
        value = _ci_get(record, key)
        if value:
            return str(value)
    return fallback_id


def _to_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"true", "1", "yes"}:
            return True
        if low in {"false", "0", "no"}:
            return False
    return None


def _extract_node_attrs(record: dict[str, Any]) -> dict[str, Any]:
    props = _ci_get(record, "Properties", {})
    source = props if isinstance(props, dict) else record

    attrs: dict[str, Any] = {}
    enabled = _to_bool(_ci_get(source, "enabled"))
    admin_count = _to_bool(_ci_get(source, "adminCount"))
    if enabled is None:
        enabled = _to_bool(_ci_get(source, "isEnabled"))
    if admin_count is None:
        admin_count = _to_bool(_ci_get(source, "admincount"))

    attrs["enabled"] = enabled
    attrs["adminCount"] = admin_count
    attrs["lastLogon"] = _ci_get(source, "lastLogon", _ci_get(source, "lastlogon"))
    attrs["distinguishedName"] = _ci_get(
        source, "distinguishedName", _ci_get(source, "distinguishedname")
    )
    return attrs


def _extract_items(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, dict):
        data = _ci_get(raw, "data")
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
    return []


def _member_references(entry: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = _ci_get(entry, key, [])
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    return []


def _add_unique_edge(
    edges: list[Edge],
    seen: set[tuple[str, str, str, str]],
    src_id: str,
    rel_type: str,
    dst_id: str,
    attrs: dict[str, Any] | None = None,
) -> None:
    attrs = attrs or {}
    right = str(attrs.get("right", ""))
    marker = (src_id, rel_type, dst_id, right)
    if marker in seen:
        return
    seen.add(marker)
    edges.append(Edge(src_id=src_id, rel_type=rel_type, dst_id=dst_id, attrs=attrs))


def _extract_ref_id(ref: dict[str, Any]) -> str | None:
    for key in ("ObjectIdentifier", "ObjectId", "PrincipalSID", "MemberId", "SID", "TargetSID", "UserSID"):
        value = _ci_get(ref, key)
        if value:
            return str(value)
    return None


def _extract_acl_rights(ace: dict[str, Any]) -> list[str]:
    right_name = _ci_get(ace, "RightName")
    if isinstance(right_name, str) and right_name:
        return [right_name]
    rights = _ci_get(ace, "Rights")
    if isinstance(rights, str):
        return [rights]
    if isinstance(rights, list):
        return [str(x) for x in rights if x]
    return []


def normalize_datasets(datasets: dict[str, list[dict[str, Any]]], warnings: list[str] | None = None) -> NormalizedData:
    warnings = list(warnings or [])
    nodes: list[Node] = []
    edges: list[Edge] = []
    edge_seen: set[tuple[str, str, str, str]] = set()
    node_seen: set[str] = set()

    for dataset, node_type in NODE_DATASETS.items():
        for idx, item in enumerate(datasets.get(dataset, [])):
            identifier = _extract_identifier(item)
            if not identifier:
                warnings.append(f"Skip {dataset}[{idx}] without identifier.")
                continue
            if identifier in node_seen:
                continue
            node_seen.add(identifier)
            nodes.append(
                Node(
                    id=identifier,
                    type=node_type,
                    name=_extract_name(item, identifier),
                    attrs=_extract_node_attrs(item),
                )
            )

    for dataset in ("users", "groups", "computers"):
        for item in datasets.get(dataset, []):
            src_id = _extract_identifier(item)
            if not src_id:
                continue
            for ref in _member_references(item, "MemberOf"):
                dst_id = _extract_ref_id(ref)
                if dst_id:
                    _add_unique_edge(
                        edges,
                        edge_seen,
                        src_id,
                        "MEMBER_OF",
                        dst_id,
                        {"raw_ref": f"{dataset}.MemberOf"},
                    )

    for item in datasets.get("groups", []):
        group_id = _extract_identifier(item)
        if not group_id:
            continue
        for member in _member_references(item, "Members"):
            member_id = _extract_ref_id(member)
            if member_id:
                _add_unique_edge(
                    edges,
                    edge_seen,
                    member_id,
                    "MEMBER_OF",
                    group_id,
                    {"raw_ref": "groups.Members"},
                )

    for session in datasets.get("sessions", []):
        dst_id = str(
            _ci_get(session, "ComputerSID")
            or _ci_get(session, "ComputerId")
            or _extract_identifier(session)
            or ""
        )
        if not dst_id:
            continue
        for sess in _member_references(session, "Sessions"):
            src_id = str(_ci_get(sess, "UserSID") or _extract_ref_id(sess) or "")
            if src_id:
                _add_unique_edge(
                    edges,
                    edge_seen,
                    src_id,
                    "HAS_SESSION",
                    dst_id,
                    {"raw_ref": "sessions.Sessions"},
                )

    for comp in datasets.get("computers", []):
        comp_id = _extract_identifier(comp)
        if not comp_id:
            continue
        for sess in _member_references(comp, "Sessions"):
            src_id = str(_ci_get(sess, "UserSID") or _extract_ref_id(sess) or "")
            if src_id:
                _add_unique_edge(
                    edges,
                    edge_seen,
                    src_id,
                    "HAS_SESSION",
                    comp_id,
                    {"raw_ref": "computers.Sessions"},
                )

    def collect_acl(item: dict[str, Any], default_target: str | None, raw_ref: str) -> None:
        aces = _member_references(item, "Aces")
        for ace in aces:
            principal = str(_ci_get(ace, "PrincipalSID") or _extract_ref_id(ace) or "")
            if not principal:
                continue
            for right in _extract_acl_rights(ace):
                target = str(
                    _ci_get(ace, "TargetSID")
                    or _ci_get(ace, "ObjectIdentifier")
                    or default_target
                    or ""
                )
                if not target:
                    continue
                _add_unique_edge(
                    edges,
                    edge_seen,
                    principal,
                    "ACL_RIGHT",
                    target,
                    {"right": right, "raw_ref": raw_ref},
                )

        principal = str(_ci_get(item, "PrincipalSID") or _ci_get(item, "Principal") or "")
        target = str(
            _ci_get(item, "TargetSID")
            or _ci_get(item, "TargetObjectIdentifier")
            or _ci_get(item, "ObjectIdentifier")
            or default_target
            or ""
        )
        right = str(_ci_get(item, "RightName") or _ci_get(item, "Right") or "")
        if principal and target and right:
            _add_unique_edge(
                edges,
                edge_seen,
                principal,
                "ACL_RIGHT",
                target,
                {"right": right, "raw_ref": raw_ref},
            )

    for dataset in ("users", "groups", "computers", "domains"):
        for item in datasets.get(dataset, []):
            collect_acl(item, _extract_identifier(item), f"{dataset}.Aces")

    for acl in datasets.get("acls", []):
        collect_acl(acl, _extract_identifier(acl), "acls")

    return NormalizedData(nodes=nodes, edges=edges, warnings=warnings)


def extract_data_records(raw_payload: Any) -> list[dict[str, Any]]:
    return _extract_items(raw_payload)

