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
                    title=f"Опасные ACL-права: {src_name} -> {dst_name}",
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
                        "Опасные ACL-права могут позволить захват целевых объектов и повышение привилегий."
                    ),
                    how_to_verify=[
                        "Проверьте ACL целевого объекта через BloodHound, PowerView или Get-Acl.",
                        "Подтвердите, что субъекту действительно нужны все делегированные права.",
                    ],
                    fix_plan=[
                        "Удалите избыточные ACL-права у субъекта на целевом объекте.",
                        "Используйте отдельные группы делегирования по принципу least privilege.",
                        "Внедрите регулярный пересмотр ACL для критичных объектов AD.",
                    ],
                    notes=f"Обнаруженные права: {', '.join(sorted(rights))}",
                )
            )
        return findings
