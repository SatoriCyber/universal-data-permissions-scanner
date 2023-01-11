from dataclasses import dataclass
from typing import List, Tuple

from aws_ptrp.principals import Principal
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.ptrp_allowed_lines.allowed_line import (
    PrincipalNodeBase,
)


@dataclass
class NoEntityPrincipal(PrincipalNodeBase):
    stmt_principal: Principal

    def __repr__(self):
        return self.stmt_principal.__repr__()

    def __eq__(self, other):
        return self.stmt_principal.__eq__(other.stmt_principal)

    def __hash__(self):
        return hash(self.stmt_principal.__hash__())

    # impl PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return self.stmt_principal

    # impl PrincipalPoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return []

    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        return []
