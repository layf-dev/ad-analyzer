from __future__ import annotations

import networkx as nx

from ad_analyzer.analyzers.acl_dangerous import DangerousAclAnalyzer
from ad_analyzer.analyzers.admincount import AdminCountAnalyzer
from ad_analyzer.analyzers.base import Analyzer
from ad_analyzer.analyzers.dcsync import DCSyncAnalyzer
from ad_analyzer.analyzers.group_privilege import GroupPrivilegeAnalyzer
from ad_analyzer.model.types import Finding, SEVERITY_ORDER


def default_analyzers() -> list[Analyzer]:
    return [
        GroupPrivilegeAnalyzer(),
        AdminCountAnalyzer(),
        DangerousAclAnalyzer(),
        DCSyncAnalyzer(),
    ]


def run_all_analyzers(graph: nx.MultiDiGraph) -> list[Finding]:
    findings: list[Finding] = []
    for analyzer in default_analyzers():
        findings.extend(analyzer.run(graph))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.title))
    return findings

