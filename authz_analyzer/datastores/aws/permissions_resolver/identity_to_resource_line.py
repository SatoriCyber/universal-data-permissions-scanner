from dataclasses import dataclass
from typing import Optional, List

from authz_analyzer.datastores.aws.permissions_resolver.identity_to_resource_nodes_base import (
    IdentityNodeBase,
    PathIdentityPoliciesNode,
    PathRoleIdentityNode,
    TargetPolicyNode,
    ResourceNodeBase,
    IdentityPoliciesNodeBase,
)
from authz_analyzer.models.model import (
    Identity,
    Asset,
    AuthzPathElement,
)
from authz_analyzer.datastores.aws.iam.policy.principal import StmtPrincipal


@dataclass
class IdentityToResourceLine:
    identity_node: IdentityNodeBase
    path_identity_policies_node: Optional[PathIdentityPoliciesNode]
    path_role_identity_nodes: List[PathRoleIdentityNode]
    target_policy_node: TargetPolicyNode
    resource_node: ResourceNodeBase

    def get_asset_to_report(self) -> Asset:
        return Asset(name=self.resource_node.get_resource_name(), type=self.resource_node.get_asset_type())

    def get_identity_to_report(self) -> Identity:
        identity_principal_to_report: StmtPrincipal = self.identity_node.get_stmt_principal()
        identity_type = identity_principal_to_report.principal_type.to_identity_type()
        return Identity(
            id=identity_principal_to_report.get_arn(), type=identity_type, name=identity_principal_to_report.get_name()
        )

    def get_path_elements_to_report(self) -> List[AuthzPathElement]:
        path: List[AuthzPathElement] = [
            path_node.get_authz_path_element() for path_node in self.path_role_identity_nodes
        ]
        if self.path_identity_policies_node:
            path.insert(0, self.path_identity_policies_node.get_authz_path_element())
        path.append(self.target_policy_node.get_authz_path_element())
        return path

    def get_identity_principal_to_policy_evaluation(self) -> StmtPrincipal:
        if self.path_role_identity_nodes:
            return self.path_role_identity_nodes[-1].path_role_identity_base.get_stmt_principal()
        else:
            return self.identity_node.get_stmt_principal()

    def get_identity_policies_base_to_policy_evaluation(self) -> IdentityPoliciesNodeBase:
        if self.path_role_identity_nodes:
            return self.path_role_identity_nodes[-1].path_role_identity_base
        elif self.path_identity_policies_node:
            return self.path_identity_policies_node.path_identity_policies_base
        else:
            return self.identity_node
