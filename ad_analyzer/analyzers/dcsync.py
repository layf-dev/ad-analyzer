from __future__ import annotations

from collections import defaultdict

import networkx as nx

from ad_analyzer.analyzers.base import Analyzer
from ad_analyzer.graph.queries import iter_acl_edges, node_to_affected
from ad_analyzer.model.types import Evidence, Severity, create_finding


DCSYNC_RIGHTS = {
    "replicating directory changes",
    "replicating directory changes all",
    "replicating directory changes in filtered set",
}


def _is_probable_dc_account(graph: nx.MultiDiGraph, principal_id: str) -> bool:
    data = graph.nodes.get(principal_id, {})
    node_type = str(data.get("type", "")).upper()
    name = str(data.get("name", "")).upper()
    attrs = data.get("attrs") or {}
    dn = str(attrs.get("distinguishedName", "")).upper()

    if node_type == "COMPUTER" and "DOMAIN CONTROLLERS" in dn:
        return True
    if node_type == "COMPUTER" and ("DC" in name or name.endswith("$")):
        return True
    return False


class DCSyncAnalyzer(Analyzer):
    name = "dcsync"

    def run(self, graph: nx.MultiDiGraph) -> list:
        grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
        refs: dict[tuple[str, str], set[str]] = defaultdict(set)

        for src, dst, data in iter_acl_edges(graph):
            target_type = str(graph.nodes.get(dst, {}).get("type", ""))
            if target_type != "DOMAIN":
                continue
            right = str(data.get("right", "")).strip().lower()
            if right not in DCSYNC_RIGHTS:
                continue
            grouped[(src, dst)].add(right)
            if data.get("raw_ref"):
                refs[(src, dst)].add(str(data["raw_ref"]))

        findings = []
        for (src, dst), rights in grouped.items():
            probable_dc = _is_probable_dc_account(graph, src)
            severity = Severity.HIGH if probable_dc else Severity.CRITICAL
            src_name = graph.nodes.get(src, {}).get("name", src)
            dst_name = graph.nodes.get(dst, {}).get("name", dst)

            findings.append(
                create_finding(
                    title=f"DCSync-capable principal detected: {src_name} -> {dst_name}",
                    severity=severity,
                    category="DCSYNC",
                    affected_objects=[node_to_affected(graph, src), node_to_affected(graph, dst)],
                    evidence=Evidence(
                        edges=[
                            {
                                "src_id": src,
                                "rel_type": "ACL_RIGHT",
                                "dst_id": dst,
                                "rights": sorted(rights),
                            }
                        ],
                        path=[],
                        raw_refs=sorted(refs[(src, dst)]),
                    ),
                    why_risky=(
                        "DCSync rights can expose NTDS secrets (including privileged account hashes) "
                        "and may lead to full domain compromise."
                    ),
                    how_to_verify=[
                        "Review replication rights delegated on the domain object.",
                        "Confirm principal is an approved DC or strictly required service.",
                    ],
                    fix_plan=[
                        "Remove replication rights from non-required principals.",
                        "Keep DCSync rights only for domain controllers and approved services.",
                        "Enable monitoring for replication and domain ACL changes.",
                    ],
                    notes=f"DCSync rights: {', '.join(sorted(rights))}",
                )
            )
        return findings

