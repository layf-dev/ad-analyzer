from __future__ import annotations

import networkx as nx

from ad_analyzer.analyzers.base import Analyzer
from ad_analyzer.graph.queries import (
    get_privileged_group_ids,
    node_to_affected,
    shortest_membership_path,
)
from ad_analyzer.model.types import Evidence, Severity, create_finding


class GroupPrivilegeAnalyzer(Analyzer):
    name = "group_privilege"

    def run(self, graph: nx.MultiDiGraph) -> list:
        findings = []
        privileged_group_ids = get_privileged_group_ids(graph)
        if not privileged_group_ids:
            return findings

        for node_id, data in graph.nodes(data=True):
            if data.get("type") != "USER":
                continue
            best_path: list[str] | None = None
            best_group: str | None = None
            for privileged_id in privileged_group_ids:
                path = shortest_membership_path(graph, node_id, privileged_id)
                if path is None:
                    continue
                if best_path is None or len(path) < len(best_path):
                    best_path = path
                    best_group = privileged_id

            if best_path is None or best_group is None:
                continue

            target_name = str(graph.nodes[best_group].get("name", best_group))
            is_direct_da_path = len(best_path) == 2 and "domain admins" in target_name.lower()
            severity = Severity.CRITICAL if is_direct_da_path else Severity.HIGH

            findings.append(
                create_finding(
                    title=(
                        "User reaches privileged group via nested membership: "
                        f"{data.get('name')} -> {target_name}"
                    ),
                    severity=severity,
                    category="GROUP_PRIVILEGE",
                    affected_objects=[node_to_affected(graph, node_id), node_to_affected(graph, best_group)],
                    evidence=Evidence(
                        edges=[
                            {
                                "src_id": best_path[i],
                                "rel_type": "MEMBER_OF",
                                "dst_id": best_path[i + 1],
                            }
                            for i in range(len(best_path) - 1)
                        ],
                        path=best_path,
                        raw_refs=["groups.Members", "users.MemberOf"],
                    ),
                    why_risky=(
                        "Nested membership can hide real privilege level. "
                        "A user can become admin through multiple groups, "
                        "which increases lateral movement and escalation risk."
                    ),
                    how_to_verify=[
                        "Build a MEMBER_OF path in BloodHound from user to privileged group.",
                        "Validate business need for each link in the membership chain.",
                    ],
                    fix_plan=[
                        "Reduce deep nesting for privileged access groups.",
                        "Remove unnecessary user/group membership in the chain.",
                        "Document and enforce least-privilege RBAC with periodic review.",
                    ],
                )
            )
        return findings

