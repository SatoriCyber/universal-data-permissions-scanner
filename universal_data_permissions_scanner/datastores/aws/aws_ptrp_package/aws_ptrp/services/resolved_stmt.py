from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from aws_ptrp.principals import PrincipalBase
from aws_ptrp.services.service_action_base import ServiceActionBase
from aws_ptrp.services.service_actions_resolver_base import ResolvedActionsSingleStmt
from aws_ptrp.services.service_resource_base import ServiceResourceBase


@dataclass
class StmtResourcesToResolveCtx:
    service_resources: Set[ServiceResourceBase]
    resolved_stmt_principals: Set[PrincipalBase]
    resolved_stmt_actions: Set[ServiceActionBase]
    stmt_relative_id_resource_regexes: List[str]
    is_condition_exists: bool
    stmt_name: Optional[str]
    stmt_parent_arn: str
    policy_name: Optional[str]


@dataclass
class ResolvedSingleStmt:
    resolved_stmt_principals: Set[PrincipalBase]
    resolved_stmt_resources: Dict[ServiceResourceBase, ResolvedActionsSingleStmt]
    is_condition_exists: bool
    stmt_name: Optional[str]
    stmt_parent_arn: str
    policy_name: Optional[str]
    # add here condition keys, tags, etc.. (single stmt scope)

    def __hash__(self) -> int:
        return hash(self.stmt_name) + hash(self.stmt_parent_arn) + hash(self.policy_name)

    def __eq__(self, other):
        return (
            self.stmt_parent_arn == other.stmt_parent_arn
            and self.policy_name == other.policy_name
            and self.stmt_name == other.stmt_name
        )

    @classmethod
    def load(
        cls,
        stmt_ctx: StmtResourcesToResolveCtx,
        resolved_stmt_resources: Dict[ServiceResourceBase, ResolvedActionsSingleStmt],
    ) -> 'ResolvedSingleStmt':
        return cls(
            resolved_stmt_principals=stmt_ctx.resolved_stmt_principals,
            resolved_stmt_resources=resolved_stmt_resources,
            is_condition_exists=stmt_ctx.is_condition_exists,
            stmt_name=stmt_ctx.stmt_name,
            stmt_parent_arn=stmt_ctx.stmt_parent_arn,
            policy_name=stmt_ctx.policy_name,
        )

    def retain_resolved_stmt_resources(self):
        # get all service resources with empty resolved stmt actions
        service_resources_to_delete = [
            x[0] for x in self.resolved_stmt_resources.items() if not x[1].resolved_stmt_actions
        ]
        # delete all these keys from the resolved_stmt_resources
        for service_resource_to_delete in service_resources_to_delete:
            del self.resolved_stmt_resources[service_resource_to_delete]


class ResolvedSingleStmtGetter(ABC):
    @abstractmethod
    def get(self) -> ResolvedSingleStmt:
        pass
