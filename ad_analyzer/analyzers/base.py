from __future__ import annotations

from abc import ABC, abstractmethod

import networkx as nx

from ad_analyzer.model.types import Finding


class Analyzer(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, graph: nx.MultiDiGraph) -> list[Finding]:
        raise NotImplementedError

