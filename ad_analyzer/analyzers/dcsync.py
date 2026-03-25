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
    if node_type != "COMPUTER":
        return False
    attrs = data.get("attrs") or {}
    dn = str(attrs.get("distinguishedName", "")).upper()

    # Prefer conservative classification: mark as probable DC only on strong signals.
    if "OU=DOMAIN CONTROLLERS" in dn:
        return True

    primary_group = str(attrs.get("primaryGroupID", "")).strip()
    if primary_group == "516":
        return True

    user_account_control = attrs.get("userAccountControl", attrs.get("useraccountcontrol"))
    try:
        if user_account_control is not None and int(user_account_control) & 0x2000:
            return True
    except (TypeError, ValueError):
        pass

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
                    title=f"Обнаружен субъект с DCSync-возможностями: {src_name} -> {dst_name}",
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
                        "Права DCSync могут раскрыть секреты NTDS (включая хэши привилегированных учётных записей) "
                        "и привести к полной компрометации домена."
                    ),
                    how_to_verify=[
                        "Проверьте, кому делегированы права репликации на объекте домена.",
                        "Подтвердите, что субъект — утверждённый DC или строго необходимый сервис.",
                    ],
                    fix_plan=[
                        "Удалите права репликации у субъектов, которым они не нужны.",
                        "Оставьте права DCSync только контроллерам домена и утверждённым сервисам.",
                        "Включите мониторинг репликации и изменений ACL домена.",
                    ],
                    notes=f"Права DCSync: {', '.join(sorted(rights))}",
                )
            )
        return findings
