from typing import List
import networkx as nx

from authz_analyzer.writers import BaseWriter
from authz_analyzer.models.graph_model import Node, ResourceNode
from authz_analyzer.models.model import AuthzEntry, AuthzPathElement


def export(graph: nx.DiGraph, start_node: Node, end_node: Node, writer: BaseWriter):
    for grant_path in nx.all_simple_paths(graph, start_node, end_node):
        identity:Node = grant_path[1]
        asset: ResourceNode = grant_path[-2]
        role_path:List[Node] = grant_path[2:-2]
        authz_path_elements = [AuthzPathElement(role.name, role.name, "Role", "") for role in role_path]

        entry = AuthzEntry(asset=asset.name, permission=asset.permission_level, identity=identity.name, path=authz_path_elements)
        writer.write_entry(entry)