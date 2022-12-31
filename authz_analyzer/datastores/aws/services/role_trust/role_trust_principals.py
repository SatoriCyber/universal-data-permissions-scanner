from dataclasses import dataclass
from logging import Logger
import itertools
from typing import Dict, List, Optional, Set

from authz_analyzer.datastores.aws.iam.policy.principal import StmtPrincipal, StmtPrincipals
from authz_analyzer.datastores.aws.principals.principal_type import PrincipalType
from authz_analyzer.datastores.aws.services.role_trust.role_trust_actions import RoleTrustAction, RoleTrustActionType


@dataclass
class ResolvedPrincipalActions:
    actions: Set[RoleTrustAction]

    def add(self, actions: Set[RoleTrustAction]):
        self.actions = self.actions.union(actions)

    @classmethod
    def load(
        cls,
        actions: Set[RoleTrustAction],
    ) -> 'ResolvedPrincipalActions':
        return cls(actions=actions)


@dataclass
class RoleTrustServicePrincipalsResolver:
    resolved_principals: List[Dict[StmtPrincipal, ResolvedPrincipalActions]]

    def is_empty(self) -> bool:
        return len(self.resolved_principals) == 0

    def add(self, other: 'RoleTrustServicePrincipalsResolver'):
        self.resolved_principals.extend(other.resolved_principals)

    def get_trusted_principals(self) -> List[StmtPrincipal]:
        return list(itertools.chain.from_iterable(map(lambda x: x.keys(), self.resolved_principals)))

    @staticmethod
    def get_relevant_assume_action_by_principal_type(principal_type: PrincipalType) -> Optional[RoleTrustActionType]:
        if principal_type == PrincipalType.WEB_IDENTITY_SESSION:
            return RoleTrustActionType.ASSUME_ROLE_WITH_WEB_IDENTITY
        elif principal_type == PrincipalType.SAML_SESSION:
            return RoleTrustActionType.ASSUME_ROLE_WITH_SAML
        elif principal_type == PrincipalType.AWS_STS_FEDERATED_USER_SESSION:
            # can't assume role with federated user
            return None
        else:
            return RoleTrustActionType.ASSUME_ROLE

    @classmethod
    def load_from_single_stmt(
        cls,
        logger: Logger,
        policy_principals: StmtPrincipals,
        resolved_actions: Set[RoleTrustAction],
    ) -> 'RoleTrustServicePrincipalsResolver':
        resolved_principals: Dict[StmtPrincipal, ResolvedPrincipalActions] = dict()
        for smt_principal in policy_principals.principals:
            relevant_assume_role = RoleTrustServicePrincipalsResolver.get_relevant_assume_action_by_principal_type(
                smt_principal.principal_type
            )
            if relevant_assume_role:
                resolved_actions_for_curr_principal = set(
                    RoleTrustAction.get_relevant_actions_for_assumed_type(logger, relevant_assume_role)
                ).intersection(resolved_actions)
                resolved_principal_actions: Optional[ResolvedPrincipalActions] = resolved_principals.get(smt_principal)
                if resolved_principal_actions:
                    resolved_principal_actions.add(resolved_actions_for_curr_principal)
                else:
                    resolved_principals[smt_principal] = ResolvedPrincipalActions.load(
                        resolved_actions_for_curr_principal
                    )

        return cls(resolved_principals=[resolved_principals])
