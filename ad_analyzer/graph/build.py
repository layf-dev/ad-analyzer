from __future__ import annotations

import networkx as nx

from ad_analyzer.model.types import Edge, Node


def build_graph(nodes: list[Node], edges: list[Edge]) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    for node in nodes:
        graph.add_node(node.id, type=node.type.value, name=node.name, attrs=node.attrs)
    for edge in edges:
        attrs = dict(edge.attrs)
        attrs["rel_type"] = edge.rel_type
        graph.add_edge(edge.src_id, edge.dst_id, **attrs)
    return graph

