from __future__ import annotations

from typing import Any

import networkx as nx

from ad_analyzer.model.types import AffectedObject


PRIVILEGED_GROUPS = {
    "domain admins",
    "enterprise admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
}


def normalize_group_name(name: str) -> str:
    return name.split("@", 1)[0].strip().lower()


def get_privileged_group_ids(graph: nx.MultiDiGraph) -> set[str]:
    result: set[str] = set()
    for node_id, data in graph.nodes(data=True):
        if data.get("type") != "GROUP":
            continue
        name = str(data.get("name", ""))
        if normalize_group_name(name) in PRIVILEGED_GROUPS:
            result.add(node_id)
    return result


def member_of_graph(graph: nx.MultiDiGraph) -> nx.DiGraph:
    g = nx.DiGraph()
    for src, dst, data in graph.edges(data=True):
        if data.get("rel_type") == "MEMBER_OF":
            g.add_edge(src, dst)
    return g


def shortest_membership_path(
    graph: nx.MultiDiGraph,
    src_id: str,
    dst_id: str,
    membership_graph: nx.DiGraph | None = None,
) -> list[str] | None:
    g = membership_graph if membership_graph is not None else member_of_graph(graph)
    try:
        return nx.shortest_path(g, src_id, dst_id)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None


def node_to_affected(graph: nx.MultiDiGraph, node_id: str) -> AffectedObject:
    data = graph.nodes.get(node_id, {})
    return AffectedObject(
        id=node_id,
        type=str(data.get("type", "UNKNOWN")),
        name=str(data.get("name", node_id)),
    )


def is_privileged_target(graph: nx.MultiDiGraph, node_id: str) -> bool:
    node = graph.nodes.get(node_id, {})
    node_type = str(node.get("type", ""))
    if node_type == "DOMAIN":
        return True
    if node_type == "GROUP":
        return normalize_group_name(str(node.get("name", ""))) in PRIVILEGED_GROUPS
    return False


def iter_acl_edges(graph: nx.MultiDiGraph) -> list[tuple[str, str, dict[str, Any]]]:
    rows: list[tuple[str, str, dict[str, Any]]] = []
    for src, dst, data in graph.edges(data=True):
        if data.get("rel_type") == "ACL_RIGHT":
            rows.append((src, dst, data))
    return rows
