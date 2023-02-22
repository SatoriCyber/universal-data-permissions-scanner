from dataclasses import dataclass
from typing import List

from aws_ptrp.iam.policy.policy_document import PolicyDocumentCtx
from aws_ptrp.principals import Principal
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import PrincipalAndPoliciesNodeBase


@dataclass
class NoEntityPrincipal(PrincipalAndPoliciesNodeBase):
    stmt_principal: Principal

    def __repr__(self):
        return self.get_node_arn()

    def __eq__(self, other):
        return self.get_node_arn() == other.get_node_arn()

    def __hash__(self):
        return hash(self.get_node_arn())

    # # impl PrincipalAndPoliciesNodeBase
    # def get_permission_boundary(self) -> Optional[PolicyDocument]:
    #     return None

    # def get_session_policies(self) -> List[PolicyDocument]:
    #     return []

    # NodeBase
    def get_node_arn(self) -> str:
        return self.stmt_principal.get_arn()

    def get_node_name(self) -> str:
        return self.stmt_principal.get_name()

    # impl PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return self.stmt_principal

    # impl PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return []

    def get_inline_policies_ctx(self) -> List[PolicyDocumentCtx]:
        return []
