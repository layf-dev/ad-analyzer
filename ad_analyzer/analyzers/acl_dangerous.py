from __future__ import annotations

from collections import defaultdict

import networkx as nx

from ad_analyzer.analyzers.base import Analyzer
from ad_analyzer.graph.queries import is_privileged_target, iter_acl_edges, node_to_affected
from ad_analyzer.model.types import Evidence, Severity, create_finding


DANGEROUS_RIGHTS = {
    "genericall",
    "genericwrite",
    "writedacl",
    "writeowner",
    "allextendedrights",
}

CRITICAL_RIGHTS = {"genericall", "writedacl", "writeowner"}


class DangerousAclAnalyzer(Analyzer):
    name = "acl_dangerous"

    def run(self, graph: nx.MultiDiGraph) -> list:
        grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
        raw_refs: dict[tuple[str, str], set[str]] = defaultdict(set)

        for src, dst, data in iter_acl_edges(graph):
            right = str(data.get("right", "")).strip()
            if not right:
                continue
            if right.lower() not in DANGEROUS_RIGHTS:
                continue
            grouped[(src, dst)].add(right)
            if data.get("raw_ref"):
                raw_refs[(src, dst)].add(str(data["raw_ref"]))

        findings = []
        for (src, dst), rights in grouped.items():
            privileged = is_privileged_target(graph, dst)
            low_rights = {x.lower() for x in rights}
            critical_right = any(x in CRITICAL_RIGHTS for x in low_rights)

            if privileged and critical_right:
                severity = Severity.CRITICAL
            elif privileged:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM

            src_name = graph.nodes.get(src, {}).get("name", src)
            dst_name = graph.nodes.get(dst, {}).get("name", dst)

            findings.append(
                create_finding(
                    title=f"Dangerous ACL rights: {src_name} -> {dst_name}",
                    severity=severity,
                    category="ACL",
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
                        raw_refs=sorted(raw_refs[(src, dst)]),
                    ),
                    why_risky=(
                        "Dangerous ACL rights can allow takeover of target objects and privilege escalation."
                    ),
                    how_to_verify=[
                        "Inspect target ACL using BloodHound, PowerView, or Get-Acl.",
                        "Confirm whether principal truly requires each delegated right.",
                    ],
                    fix_plan=[
                        "Remove excessive ACL rights from principal on the target object.",
                        "Use dedicated least-privilege delegation groups.",
                        "Schedule periodic ACL review for critical AD objects.",
                    ],
                    notes=f"Detected rights: {', '.join(sorted(rights))}",
                )
            )
        return findings

