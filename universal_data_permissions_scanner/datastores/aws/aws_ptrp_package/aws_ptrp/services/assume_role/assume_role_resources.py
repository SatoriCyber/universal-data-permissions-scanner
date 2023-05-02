import re
from dataclasses import dataclass
from logging import Logger
from typing import Dict, Generator, List, Optional, Set

from aws_ptrp.iam.iam_roles import IAMRole
from aws_ptrp.iam.policy.policy_document_utils import fix_stmt_regex_to_valid_regex
from aws_ptrp.principals import Principal, PrincipalBase
from aws_ptrp.ptrp_models.ptrp_model import AwsPrincipalType
from aws_ptrp.services import (
    ResolvedActionsSingleStmt,
    ResolvedSingleStmt,
    ResolvedSingleStmtGetter,
    ServiceActionBase,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
    StmtResourcesToResolveCtx,
)
from aws_ptrp.services.assume_role.assume_role_actions import AssumeRoleAction, AssumeRoleActionType


@dataclass
class ResolvedAssumeRoleActions(ResolvedActionsSingleStmt):
    actions: Set[AssumeRoleAction]

    @property
    def resolved_stmt_actions(self) -> Set[ServiceActionBase]:
        return self.actions  # type: ignore[return-value]

    def add(self, actions: Set[AssumeRoleAction]):
        self.actions = self.actions.union(actions)

    @classmethod
    def load(
        cls,
        actions: Set[AssumeRoleAction],
    ) -> 'ResolvedAssumeRoleActions':
        return cls(actions=actions)


@dataclass
class AssumeRoleResolvedStmt(ResolvedSingleStmtGetter):
    resolved_stmt: ResolvedSingleStmt

    def get(self) -> ResolvedSingleStmt:
        return self.resolved_stmt

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

    def yield_trusted_principals(self, iam_role: IAMRole) -> Generator[PrincipalBase, None, None]:
        for resolved_principal_base in self.resolved_stmt.resolved_stmt_principals:
            relevant_assume_role: Optional[
                AssumeRoleActionType
            ] = AssumeRoleResolvedStmt.get_relevant_assume_action_by_principal_type(
                resolved_principal_base.get_principal().principal_type
            )
            if relevant_assume_role is None:
                continue

            resolved_actions: Optional[ResolvedActionsSingleStmt] = self.resolved_stmt.resolved_stmt_resources.get(
                iam_role
            )
            if resolved_actions is None:
                continue

            if not any(
                isinstance(resolved_action, AssumeRoleAction) and resolved_action.action_type == relevant_assume_role
                for resolved_action in resolved_actions.resolved_stmt_actions
            ):
                continue

            yield resolved_principal_base


@dataclass
class AssumeRoleServiceResourcesResolver(ServiceResourcesResolverBase):
    resolved_stmts: List[AssumeRoleResolvedStmt]

    def get_resolved_stmts(self) -> List[ResolvedSingleStmtGetter]:
        return self.resolved_stmts  # type: ignore[return-value]

    def yield_trusted_principals(self, iam_role: IAMRole) -> Generator[PrincipalBase, None, None]:
        for resolved_stmt in self.resolved_stmts:
            yield from resolved_stmt.yield_trusted_principals(iam_role)

    def is_trusted_principal(self, iam_role: IAMRole, principal: Principal) -> bool:
        for trusted_principal_base in self.yield_trusted_principals(iam_role):
            if trusted_principal_base.get_principal().contains(principal):
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
        cls, _logger: Logger, stmt_ctx: StmtResourcesToResolveCtx, not_resource_annotated: bool
    ) -> ServiceResourcesResolverBase:
        resolved_iam_roles_actions: Dict[IAMRole, ResolvedAssumeRoleActions] = dict()
        assume_role_actions = set(
            [
                resolved_stmt_action
                for resolved_stmt_action in stmt_ctx.resolved_stmt_actions
                if isinstance(resolved_stmt_action, AssumeRoleAction)
            ]
        )

        for stmt_relative_id_regex in stmt_ctx.stmt_relative_id_resource_regexes:
            yield_iam_roles = AssumeRoleServiceResourcesResolver._yield_resolve_resources_from_stmt_relative_id_regex(
                stmt_relative_id_regex, stmt_ctx.service_resources
            )
            for resolved_iam_role in yield_iam_roles:
                resolved_iam_roles_actions[resolved_iam_role] = ResolvedAssumeRoleActions.load(
                    assume_role_actions.copy()
                )

        if not_resource_annotated:
            assumed_roles = [resource for resource in stmt_ctx.service_resources if isinstance(resource, IAMRole)]
            for role in assumed_roles:
                if role not in resolved_iam_roles_actions:
                    resolved_iam_roles_actions[role] = ResolvedAssumeRoleActions.load(assume_role_actions.copy())
                else:
                    resolved_iam_roles_actions.pop(role)

        resolved_stmt: ResolvedSingleStmt = ResolvedSingleStmt.load(stmt_ctx, resolved_iam_roles_actions)  # type: ignore
        return cls(resolved_stmts=[AssumeRoleResolvedStmt(resolved_stmt=resolved_stmt)])
