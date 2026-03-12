from __future__ import annotations

from ad_analyzer.analyzers import run_all_analyzers
from ad_analyzer.graph.build import build_graph
from ad_analyzer.model.types import Edge, Node, NodeType


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

