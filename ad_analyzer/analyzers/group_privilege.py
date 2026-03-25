from __future__ import annotations

import networkx as nx

from ad_analyzer.analyzers.base import Analyzer
from ad_analyzer.graph.queries import (
    get_privileged_group_ids,
    member_of_graph,
    node_to_affected,
    normalize_group_name,
    shortest_membership_path,
)
from ad_analyzer.model.types import Evidence, Severity, create_finding


class GroupPrivilegeAnalyzer(Analyzer):
    name = "group_privilege"

    @staticmethod
    def _is_direct_domain_admins_path(path: list[str], target_name: str) -> bool:
        return len(path) == 2 and normalize_group_name(target_name) == "domain admins"

    @staticmethod
    def _candidate_rank(group_id: str, target_name: str, path: list[str]) -> tuple[int, str, str]:
        # Stable tie-breaker: prefer direct Domain Admins path, then lexical order.
        is_direct_da = GroupPrivilegeAnalyzer._is_direct_domain_admins_path(path, target_name)
        return (0 if is_direct_da else 1, normalize_group_name(target_name), group_id)

    def run(self, graph: nx.MultiDiGraph) -> list:
        findings = []
        privileged_group_ids = sorted(
            get_privileged_group_ids(graph),
            key=lambda gid: (normalize_group_name(str(graph.nodes[gid].get("name", gid))), gid),
        )
        if not privileged_group_ids:
            return findings
        membership_graph = member_of_graph(graph)

        for node_id, data in graph.nodes(data=True):
            if data.get("type") != "USER":
                continue
            best_path: list[str] | None = None
            best_group: str | None = None
            for privileged_id in privileged_group_ids:
                path = shortest_membership_path(
                    graph,
                    node_id,
                    privileged_id,
                    membership_graph=membership_graph,
                )
                if path is None:
                    continue
                if best_path is None or len(path) < len(best_path):
                    best_path = path
                    best_group = privileged_id
                    continue
                if len(path) == len(best_path) and best_group is not None:
                    target_name = str(graph.nodes[privileged_id].get("name", privileged_id))
                    best_target_name = str(graph.nodes[best_group].get("name", best_group))
                    if self._candidate_rank(privileged_id, target_name, path) < self._candidate_rank(
                        best_group, best_target_name, best_path
                    ):
                        best_path = path
                        best_group = privileged_id

            if best_path is None or best_group is None:
                continue

            target_name = str(graph.nodes[best_group].get("name", best_group))
            is_direct_da_path = self._is_direct_domain_admins_path(best_path, target_name)
            severity = Severity.CRITICAL if is_direct_da_path else Severity.HIGH

            findings.append(
                create_finding(
                    title=(
                        "Пользователь достигает привилегированной группы через вложенное членство: "
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
                        "Вложенное членство может скрывать реальный уровень привилегий. "
                        "Пользователь может стать администратором через цепочку групп, "
                        "что повышает риск lateral movement и escalation."
                    ),
                    how_to_verify=[
                        "Постройте путь MEMBER_OF в BloodHound от пользователя до привилегированной группы.",
                        "Подтвердите бизнес-необходимость каждого звена в цепочке членства.",
                    ],
                    fix_plan=[
                        "Сократите глубину вложенности для групп с привилегированным доступом.",
                        "Удалите лишние связи пользователь/группа в цепочке.",
                        "Зафиксируйте и соблюдайте RBAC по принципу least privilege с регулярным пересмотром.",
                    ],
                )
            )
        return findings
