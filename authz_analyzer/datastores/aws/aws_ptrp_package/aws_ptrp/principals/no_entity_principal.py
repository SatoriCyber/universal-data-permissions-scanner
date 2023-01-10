from dataclasses import dataclass
from typing import List, Tuple

from aws_ptrp.iam.policy.principal import StmtPrincipal
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.permissions_resolver.identity_to_resource_line import (
    IdentityNodeBase,
)


@dataclass
class NoEntityPrincipal(IdentityNodeBase):
    stmt_principal: StmtPrincipal

    def __repr__(self):
        return self.stmt_principal.__repr__()

    def __eq__(self, other):
        return self.stmt_principal.__eq__(other.stmt_principal)

    def __hash__(self):
        return hash(self.stmt_principal.__hash__())

    # impl IdentityNodeBase
    def get_stmt_principal(self) -> StmtPrincipal:
        return self.stmt_principal

    # impl IdentityPoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return []

    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        return []
