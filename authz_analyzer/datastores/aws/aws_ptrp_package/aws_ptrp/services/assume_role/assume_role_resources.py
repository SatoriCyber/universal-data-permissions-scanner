import re
from dataclasses import dataclass
from logging import Logger
from typing import Dict, Generator, List, Optional, Set

from aws_ptrp.iam.iam_roles import IAMRole
from aws_ptrp.iam.policy.policy_document_utils import fix_stmt_regex_to_valid_regex
from aws_ptrp.principals import Principal
from aws_ptrp.ptrp_models.ptrp_model import AwsPrincipalType
from aws_ptrp.services import (
    ResolvedActionsSingleStmt,
    ResolvedResourcesSingleStmt,
    ServiceActionBase,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
)
from aws_ptrp.services.assume_role.assume_role_actions import AssumeRoleAction, AssumeRoleActionType


@dataclass
class ResolvedAssumeRoleActions(ResolvedActionsSingleStmt):
    actions: Set[AssumeRoleAction]

    @property
    def resolved_stmt_actions(self) -> Set[ServiceActionBase]:
        return self.actions  # type: ignore[return-value]

    def subtract(self, other: 'ResolvedActionsSingleStmt'):
        if isinstance(other, ResolvedAssumeRoleActions):
            self.actions = self.actions.difference(other.actions)

    def add(self, actions: Set[AssumeRoleAction]):
        self.actions = self.actions.union(actions)

    @classmethod
    def load(
        cls,
        actions: Set[AssumeRoleAction],
    ) -> 'ResolvedAssumeRoleActions':
        return cls(actions=actions)


@dataclass
class AssumeRoleResolvedStmt(ResolvedResourcesSingleStmt):
    resolved_principals: List[Principal]
    resolved_iam_roles_actions: Dict[IAMRole, ResolvedAssumeRoleActions]
    # add here condition keys, tags, etc.. (single stmt scope)

    @property
    def resolved_stmt_principals(self) -> List[Principal]:
        return self.resolved_principals

    @property
    def resolved_stmt_resources(self) -> Dict[ServiceResourceBase, ResolvedActionsSingleStmt]:
        return self.resolved_iam_roles_actions  # type: ignore[return-value]

    @staticmethod
    def get_relevant_assume_action_by_principal_type(
        principal_type: AwsPrincipalType,
    ) -> Optional[AssumeRoleActionType]:
        if principal_type == AwsPrincipalType.WEB_IDENTITY_SESSION:
            return AssumeRoleActionType.ASSUME_ROLE_WITH_WEB_IDENTITY
        elif principal_type == AwsPrincipalType.SAML_SESSION:
            return AssumeRoleActionType.ASSUME_ROLE_WITH_SAML
        elif principal_type == AwsPrincipalType.AWS_STS_FEDERATED_USER_SESSION:
            # can't assume role with federated user
            return None
        else:
            return AssumeRoleActionType.ASSUME_ROLE

    def yield_trusted_principals(self, iam_role: IAMRole) -> Generator[Principal, None, None]:
        for resolved_principal in self.resolved_principals:
            relevant_assume_role: Optional[
                AssumeRoleActionType
            ] = AssumeRoleResolvedStmt.get_relevant_assume_action_by_principal_type(resolved_principal.principal_type)
            if relevant_assume_role is None:
                continue

            resolved_actions: Optional[ResolvedAssumeRoleActions] = self.resolved_iam_roles_actions.get(iam_role)
            if resolved_actions is None:
                continue

            if not any(
                resolved_action.action_type == relevant_assume_role for resolved_action in resolved_actions.actions
            ):
                continue

            yield resolved_principal


@dataclass
class AssumeRoleServiceResourcesResolver(ServiceResourcesResolverBase):
    resolved_stmts: List[AssumeRoleResolvedStmt]

    def get_resolved_stmts(self) -> List[ResolvedResourcesSingleStmt]:
        return self.resolved_stmts  # type: ignore[return-value]

    def yield_trusted_principals(self, iam_role: IAMRole) -> Generator[Principal, None, None]:
        for resolved_stmt in self.resolved_stmts:
            yield from resolved_stmt.yield_trusted_principals(iam_role)

    def is_trusted_principal(self, iam_role: IAMRole, principal: Principal) -> bool:
        for trusted_principal in self.yield_trusted_principals(iam_role):
            if trusted_principal == principal:
                return True
        return False

    @staticmethod
    def _yield_resolve_resources_from_stmt_relative_id_regex(
        stmt_relative_id_regex: str,
        service_resources: Set[ServiceResourceBase],
    ) -> Generator[IAMRole, None, None]:
        regex = re.compile(fix_stmt_regex_to_valid_regex(stmt_relative_id_regex, with_case_sensitive=True))
        for service_resource in service_resources:
            # not using the regex match fn, stmt_relative_id_regex is without the prefix: "arn:aws:iam::"
            if regex.search(service_resource.get_resource_arn()) is not None and isinstance(service_resource, IAMRole):
                yield service_resource

    @classmethod
    def load_from_single_stmt(
        cls,
        logger: Logger,
        stmt_relative_id_regexes: List[str],
        service_resources: Set[ServiceResourceBase],
        resolved_stmt_principals: List[Principal],
        resolved_stmt_actions: Set[ServiceActionBase],
    ) -> ServiceResourcesResolverBase:
        resolved_iam_roles_actions: Dict[IAMRole, ResolvedAssumeRoleActions] = dict()
        assume_role_actions = set(
            [
                resolved_stmt_action
                for resolved_stmt_action in resolved_stmt_actions
                if isinstance(resolved_stmt_action, AssumeRoleAction)
            ]
        )

        resolved_assume_role_actions = ResolvedAssumeRoleActions.load(assume_role_actions)
        for stmt_relative_id_regex in stmt_relative_id_regexes:
            yield_iam_roles = AssumeRoleServiceResourcesResolver._yield_resolve_resources_from_stmt_relative_id_regex(
                stmt_relative_id_regex, service_resources
            )
            for resolved_iam_role in yield_iam_roles:
                resolved_iam_roles_actions[resolved_iam_role] = resolved_assume_role_actions

        return cls(
            resolved_stmts=[
                AssumeRoleResolvedStmt(
                    resolved_principals=resolved_stmt_principals, resolved_iam_roles_actions=resolved_iam_roles_actions
                )
            ]
        )
