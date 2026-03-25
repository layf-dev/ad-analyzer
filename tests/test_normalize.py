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


def test_normalize_preserves_dc_relevant_attrs() -> None:
    datasets = {
        "users": [],
        "groups": [],
        "computers": [
            {
                "ObjectIdentifier": "C1",
                "Properties": {
                    "name": "dc01",
                    "primaryGroupID": "516",
                    "userAccountControl": 8192,
                    "distinguishedName": "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
                },
            }
        ],
        "domains": [],
        "sessions": [],
        "acls": [],
    }

    normalized = normalize_datasets(datasets)
    computer = next(n for n in normalized.nodes if n.id == "C1")
    assert computer.attrs["primaryGroupID"] == "516"
    assert computer.attrs["userAccountControl"] == 8192
