from __future__ import annotations

import ad_analyzer.analyzers.group_privilege as gp
from ad_analyzer.analyzers.dcsync import DCSyncAnalyzer
from ad_analyzer.analyzers import run_all_analyzers
from ad_analyzer.analyzers.group_privilege import GroupPrivilegeAnalyzer
from ad_analyzer.graph.build import build_graph
from ad_analyzer.graph.queries import member_of_graph as original_member_of_graph
from ad_analyzer.model.types import Edge, Node, NodeType, Severity


def test_analyzers_detect_group_privilege_dcsync_and_acl() -> None:
    nodes = [
        Node(id="U1", type=NodeType.USER, name="alice", attrs={"adminCount": False}),
        Node(id="G1", type=NodeType.GROUP, name="Helpdesk", attrs={}),
        Node(id="G2", type=NodeType.GROUP, name="Domain Admins", attrs={}),
        Node(id="D1", type=NodeType.DOMAIN, name="corp.local", attrs={}),
        Node(id="U2", type=NodeType.USER, name="svc_sync", attrs={}),
    ]
    edges = [
        Edge(src_id="U1", rel_type="MEMBER_OF", dst_id="G1"),
        Edge(src_id="G1", rel_type="MEMBER_OF", dst_id="G2"),
        Edge(src_id="U1", rel_type="ACL_RIGHT", dst_id="G2", attrs={"right": "GenericAll"}),
        Edge(
            src_id="U2",
            rel_type="ACL_RIGHT",
            dst_id="D1",
            attrs={"right": "Replicating Directory Changes All"},
        ),
    ]
    graph = build_graph(nodes, edges)

    findings = run_all_analyzers(graph)
    categories = {f.category for f in findings}
    assert "GROUP_PRIVILEGE" in categories
    assert "ACL" in categories
    assert "DCSYNC" in categories


def test_group_privilege_builds_membership_graph_once(monkeypatch) -> None:
    nodes = [
        Node(id="U1", type=NodeType.USER, name="alice", attrs={}),
        Node(id="U2", type=NodeType.USER, name="bob", attrs={}),
        Node(id="G1", type=NodeType.GROUP, name="Helpdesk", attrs={}),
        Node(id="G2", type=NodeType.GROUP, name="Domain Admins", attrs={}),
    ]
    edges = [
        Edge(src_id="U1", rel_type="MEMBER_OF", dst_id="G1"),
        Edge(src_id="U2", rel_type="MEMBER_OF", dst_id="G1"),
        Edge(src_id="G1", rel_type="MEMBER_OF", dst_id="G2"),
    ]
    graph = build_graph(nodes, edges)

    calls = {"count": 0}

    def counting_member_of_graph(g):
        calls["count"] += 1
        return original_member_of_graph(g)

    monkeypatch.setattr(gp, "member_of_graph", counting_member_of_graph)

    findings = GroupPrivilegeAnalyzer().run(graph)

    assert len(findings) >= 1
    assert calls["count"] == 1


def test_group_privilege_tie_prefers_direct_domain_admins_path() -> None:
    nodes = [
        Node(id="U1", type=NodeType.USER, name="alice", attrs={}),
        Node(id="G1", type=NodeType.GROUP, name="Domain Admins", attrs={}),
        Node(id="G2", type=NodeType.GROUP, name="Enterprise Admins", attrs={}),
    ]
    edges = [
        Edge(src_id="U1", rel_type="MEMBER_OF", dst_id="G1"),
        Edge(src_id="U1", rel_type="MEMBER_OF", dst_id="G2"),
    ]
    graph = build_graph(nodes, edges)

    findings = GroupPrivilegeAnalyzer().run(graph)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.CRITICAL
    assert "-> Domain Admins" in finding.title


def test_dcsync_non_dc_computer_keeps_critical() -> None:
    nodes = [
        Node(id="C1", type=NodeType.COMPUTER, name="WS-01$", attrs={"distinguishedName": "CN=WS-01,OU=Workstations,DC=corp,DC=local"}),
        Node(id="D1", type=NodeType.DOMAIN, name="corp.local", attrs={}),
    ]
    edges = [
        Edge(
            src_id="C1",
            rel_type="ACL_RIGHT",
            dst_id="D1",
            attrs={"right": "Replicating Directory Changes All"},
        ),
    ]
    graph = build_graph(nodes, edges)

    findings = DCSyncAnalyzer().run(graph)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_dcsync_probable_dc_computer_downgrades_to_high() -> None:
    nodes = [
        Node(
            id="C1",
            type=NodeType.COMPUTER,
            name="DC01$",
            attrs={
                "distinguishedName": "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
                "primaryGroupID": "516",
                "userAccountControl": 8192,
            },
        ),
        Node(id="D1", type=NodeType.DOMAIN, name="corp.local", attrs={}),
    ]
    edges = [
        Edge(
            src_id="C1",
            rel_type="ACL_RIGHT",
            dst_id="D1",
            attrs={"right": "Replicating Directory Changes All"},
        ),
    ]
    graph = build_graph(nodes, edges)

    findings = DCSyncAnalyzer().run(graph)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
