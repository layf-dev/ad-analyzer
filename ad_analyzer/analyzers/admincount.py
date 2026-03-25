from __future__ import annotations

import networkx as nx

from ad_analyzer.analyzers.base import Analyzer
from ad_analyzer.graph.queries import PRIVILEGED_GROUPS, node_to_affected, normalize_group_name
from ad_analyzer.model.types import Evidence, Severity, create_finding


class AdminCountAnalyzer(Analyzer):
    name = "admincount"

    def run(self, graph: nx.MultiDiGraph) -> list:
        findings = []
        for node_id, data in graph.nodes(data=True):
            attrs = data.get("attrs") or {}
            admin_count = attrs.get("adminCount")
            if admin_count not in {True, 1, "1", "true", "True"}:
                continue

            node_type = str(data.get("type", "UNKNOWN"))
            node_name = str(data.get("name", node_id))
            is_privileged_group = (
                node_type == "GROUP" and normalize_group_name(node_name) in PRIVILEGED_GROUPS
            )
            severity = Severity.HIGH if is_privileged_group else Severity.MEDIUM

            findings.append(
                create_finding(
                    title=f"Установлен adminCount=true для {node_type}: {node_name}",
                    severity=severity,
                    category="ADMINCOUNT",
                    affected_objects=[node_to_affected(graph, node_id)],
                    evidence=Evidence(
                        edges=[],
                        path=[],
                        raw_refs=["Properties.adminCount", "Properties.admincount"],
                    ),
                    why_risky=(
                        "adminCount часто указывает на объекты под защитой AdminSDHolder. "
                        "Такие объекты нередко связаны с повышенными привилегиями и отключённым наследованием ACL."
                    ),
                    how_to_verify=[
                        "Проверьте значение adminCount у объекта напрямую в AD.",
                        "Проверьте наследование ACL и членство объекта в привилегированных группах.",
                    ],
                    fix_plan=[
                        "Проверьте, нужен ли объекту защищённый статус сейчас.",
                        "Удалите объект из привилегированных групп, если это больше не требуется.",
                        "После очистки прав восстановите наследование ACL.",
                    ],
                )
            )
        return findings
