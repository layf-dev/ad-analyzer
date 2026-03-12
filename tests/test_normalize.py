from __future__ import annotations

from ad_analyzer.model.normalize import normalize_datasets


def test_normalize_builds_nodes_and_edges() -> None:
    datasets = {
        "users": [
            {
                "ObjectIdentifier": "U1",
                "Properties": {"name": "alice", "adminCount": 1, "enabled": True},
                "MemberOf": [{"ObjectIdentifier": "G1"}],
            }
        ],
        "groups": [
            {"ObjectIdentifier": "G1", "Properties": {"name": "Domain Admins"}},
        ],
        "computers": [],
        "domains": [],
        "sessions": [],
        "acls": [],
    }

    normalized = normalize_datasets(datasets)
    assert len(normalized.nodes) == 2
    assert any(n.id == "U1" and n.attrs["adminCount"] is True for n in normalized.nodes)
    assert any(e.rel_type == "MEMBER_OF" and e.src_id == "U1" and e.dst_id == "G1" for e in normalized.edges)

