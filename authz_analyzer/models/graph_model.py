from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Dict, Optional

import networkx as nx

from authz_analyzer.models.model import PermissionLevel

class NodeType(Enum):
    START = auto()
    END = auto()
    GRANTED_TO = auto()
    GRANTED_BY = auto()


@dataclass
class Node:
    name: str
    type: NodeType

    def __hash__(self) -> int:
        return hash(self.name) + hash(self.type)

    @classmethod
    def create_start_node(cls):
        return cls(name="start", type=NodeType.START)

    @classmethod
    def create_end_node(cls):
        return cls(name="end", type=NodeType.END)
    
    @classmethod
    def create_granted_to(cls, name: str):
        """Usually a user or a role, but can be anything that gets grant to a resource"""
        return cls(name=name, type=NodeType.GRANTED_TO)  

    @classmethod
    def create_granter(cls, name: str):
        """Usually a role, but can be anything that gets gives access"""
        return cls(name=name, type=NodeType.GRANTED_BY)    
    

@dataclass
class ResourceNode():
    name: str
    permission_level: PermissionLevel

    def __hash__(self) -> int:
        return hash(self.name) + hash(self.permission_level)


def init_graph():
    start_node = Node.create_start_node()
    end_node = Node.create_end_node()
    graph = nx.DiGraph()
    graph.add_node(start_node)
    graph.add_node(end_node)
    return (graph, start_node, end_node)