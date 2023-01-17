from dataclasses import dataclass
from typing import List, Optional, Tuple

from aws_ptrp.principals import Principal
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import (
    PathFederatedPrincipalNode,
    PathPolicyNode,
    PathRoleNode,
    PathUserGroupNode,
    PoliciesNodeBase,
    PrincipalAndPoliciesNodeBase,
    ResourceNodeBase,
)
from aws_ptrp.ptrp_models.ptrp_model import AwsPrincipal, AwsPtrpPathNode, AwsPtrpResource


@dataclass
class PtrpAllowedLine:
    principal_node: PrincipalAndPoliciesNodeBase
    path_user_group_node: Optional[PathUserGroupNode]
    path_federated_nodes: Optional[Tuple[PathPolicyNode, PathFederatedPrincipalNode]]
    path_role_nodes: List[PathRoleNode]
    target_policy_node: PathPolicyNode
    resource_node: ResourceNodeBase

    def get_ptrp_resource_to_report(self) -> AwsPtrpResource:
        return AwsPtrpResource(
            name=self.resource_node.get_resource_name(), type=self.resource_node.get_ptrp_resource_type()
        )

    def get_principal_to_report(self) -> AwsPrincipal:
        principal_to_report: Principal = self.principal_node.get_stmt_principal()
        return AwsPrincipal(
            arn=principal_to_report.get_arn(),
            type=principal_to_report.principal_type,
            name=principal_to_report.get_name(),
        )

    def get_ptrp_path_nodes_to_report(self) -> List[AwsPtrpPathNode]:
        path: List[AwsPtrpPathNode] = []
        if self.path_user_group_node:
            path.append(self.path_user_group_node.get_ptrp_path_node())

        if self.path_federated_nodes:
            path.append(self.path_federated_nodes[0].get_ptrp_path_node())
            path.append(self.path_federated_nodes[1].get_ptrp_path_node())

        for path_role_node in self.path_role_nodes:
            path.append(path_role_node.get_ptrp_path_node())

        path.append(self.target_policy_node.get_ptrp_path_node())
        return path

    def get_principal_to_policy_evaluation(self) -> Principal:
        if self.path_role_nodes:
            return self.path_role_nodes[-1].base.get_stmt_principal()
        elif self.path_federated_nodes:
            return self.path_federated_nodes[1].get_stmt_principal()
        else:
            return self.principal_node.get_stmt_principal()

    def get_principal_policies_base_to_policy_evaluation(self) -> List[PoliciesNodeBase]:
        if self.path_role_nodes:
            return [self.path_role_nodes[-1].base]
        else:
            ret: List[PoliciesNodeBase] = [self.principal_node]
            if self.path_user_group_node:
                ret.append(self.path_user_group_node.base)
            return ret
