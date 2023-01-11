from dataclasses import dataclass
from typing import Optional, List

from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import (
    PrincipalNodeBase,
    PathPrincipalPoliciesNode,
    PathRoleNode,
    TargetPolicyNode,
    ResourceNodeBase,
    PrincipalPoliciesNodeBase,
)
from aws_ptrp.principals import Principal

from aws_ptrp.ptrp_models.ptrp_model import (
    AwsPrincipal,
    AwsPtrpResource,
    AwsPtrpPathNode,
)


@dataclass
class PtrpAllowedLine:
    principal_node: PrincipalNodeBase
    path_principal_policies_node: Optional[PathPrincipalPoliciesNode]
    path_role_nodes: List[PathRoleNode]
    target_policy_node: TargetPolicyNode
    resource_node: ResourceNodeBase

    def get_ptrp_resource_to_report(self) -> AwsPtrpResource:
        return AwsPtrpResource(
            name=self.resource_node.get_resource_name(), type=self.resource_node.get_ptrp_resource_type()
        )

    def get_principal_to_report(self) -> AwsPrincipal:
        identity_principal_to_report: Principal = self.principal_node.get_stmt_principal()
        return AwsPrincipal(
            arn=identity_principal_to_report.get_arn(),
            type=identity_principal_to_report.principal_type,
            name=identity_principal_to_report.get_name(),
        )

    def get_ptrp_path_nodes_to_report(self) -> List[AwsPtrpPathNode]:
        path: List[AwsPtrpPathNode] = [path_node.get_ptrp_path_node() for path_node in self.path_role_nodes]
        if self.path_principal_policies_node:
            path.insert(0, self.path_principal_policies_node.get_ptrp_path_node())
        path.append(self.target_policy_node.get_ptrp_path_node())
        return path

    def get_principal_to_policy_evaluation(self) -> Principal:
        if self.path_role_nodes:
            return self.path_role_nodes[-1].path_role_base.get_stmt_principal()
        else:
            return self.principal_node.get_stmt_principal()

    def get_principal_policies_base_to_policy_evaluation(self) -> PrincipalPoliciesNodeBase:
        if self.path_role_nodes:
            return self.path_role_nodes[-1].path_role_base
        elif self.path_principal_policies_node:
            return self.path_principal_policies_node.path_principal_policies_base
        else:
            return self.principal_node
