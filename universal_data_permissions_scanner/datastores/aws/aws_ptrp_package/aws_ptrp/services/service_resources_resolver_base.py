from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from logging import Logger
from typing import Dict, Generator, List, Optional, Set

from aws_ptrp.principals import Principal, PrincipalBase
from aws_ptrp.services.resolved_stmt import ResolvedSingleStmt, ResolvedSingleStmtGetter, StmtResourcesToResolveCtx
from aws_ptrp.services.service_action_base import ServiceActionBase
from aws_ptrp.services.service_actions_resolver_base import (
    MethodOnStmtActionsResultType,
    MethodOnStmtActionsType,
    ResolvedActionsSingleStmt,
)
from aws_ptrp.services.service_resource_base import ServiceResourceBase


@dataclass
class MethodOnStmtActionsResult:
    resolved_single_stmt: ResolvedSingleStmt
    result: MethodOnStmtActionsResultType

    def __hash__(self) -> int:
        return hash(self.result) + hash(self.resolved_single_stmt)

    def __eq__(self, other):
        return self.resolved_single_stmt == other.resolved_single_stmt and self.result == other.result


@dataclass
class MethodOnStmtsActionsResult:
    resolved_stmt_results: Set[MethodOnStmtActionsResult] = field(default_factory=set)


@dataclass
class ServiceResourcesResolverBase(ABC):
    @abstractmethod
    def get_resolved_stmts(self) -> List[ResolvedSingleStmtGetter]:
        pass

    def yield_resolved_stmts(self) -> Generator[ResolvedSingleStmt, None, None]:
        for resolved_stmt_getter in self.get_resolved_stmts():
            yield resolved_stmt_getter.get()

    def retain_resolved_stmts(self):
        # get all list indexes to delete (single stmt with empty resolved actions)
        stmt_indexes_to_delete = []
        curr_index = 0
        for resolved_stmt in self.yield_resolved_stmts():
            if not resolved_stmt.resolved_stmt_resources:
                stmt_indexes_to_delete.append(curr_index)
            curr_index = curr_index + 1

        element_deleted = 0
        resolved_stmts = self.get_resolved_stmts()
        for stmt_index_to_delete in stmt_indexes_to_delete:
            del resolved_stmts[stmt_index_to_delete - element_deleted]
            element_deleted = element_deleted + 1

    def apply_method_on_stmts_actions(
        self,
        method_on_stmt_actions_type: MethodOnStmtActionsType,
        principal: Principal,
        other: 'ServiceResourcesResolverBase',
    ) -> MethodOnStmtsActionsResult:
        '''apply method on resolved actions from 'self' statements with 'other' statement.
        For each statement in self & other which contains the principal, apply the method on the resolved actions for each resolved resource
        '''
        res = MethodOnStmtsActionsResult()
        for resolved_stmt in self.yield_resolved_stmts():
            if not any(
                resolved_stmt_principal_base.get_principal().contains(principal)
                for resolved_stmt_principal_base in resolved_stmt.resolved_stmt_principals
            ):
                continue
            # self stmt relevant to this principal
            resolved_actions_resources_for_intersection: Dict[ServiceResourceBase, Set[ServiceActionBase]] = {}
            for other_resolved_stmt in other.yield_resolved_stmts():
                if not any(
                    other_resolved_stmt_principal_base.get_principal().contains(principal)
                    for other_resolved_stmt_principal_base in other_resolved_stmt.resolved_stmt_principals
                ):
                    res.resolved_stmt_results.add(
                        MethodOnStmtActionsResult(
                            resolved_single_stmt=other_resolved_stmt,
                            result=MethodOnStmtActionsResultType.IGNORE_NO_OVERLAPS_TARGET_PRINCIPAL,
                        )
                    )
                    continue

                if (
                    other_resolved_stmt.is_condition_exists is True
                    and method_on_stmt_actions_type == MethodOnStmtActionsType.DIFFERENCE
                ):
                    res.resolved_stmt_results.add(
                        MethodOnStmtActionsResult(
                            resolved_single_stmt=other_resolved_stmt,
                            result=MethodOnStmtActionsResultType.IGNORE_METHOD_DIFFERENCE_CONDITION_EXISTS,
                        )
                    )
                    continue

                # other stmt relevant to this principal
                # Need to check matches on the resolved resources in these statements
                for service_resource, resolved_action_single_stmt in resolved_stmt.resolved_stmt_resources.items():
                    other_resolved_action_single_stmt: Optional[
                        ResolvedActionsSingleStmt
                    ] = other_resolved_stmt.resolved_stmt_resources.get(service_resource)

                    if not other_resolved_action_single_stmt:
                        res.resolved_stmt_results.add(
                            MethodOnStmtActionsResult(
                                resolved_single_stmt=other_resolved_stmt,
                                result=MethodOnStmtActionsResultType.IGNORE_NO_OVERLAPS_TARGET_RESOURCE,
                            )
                        )
                        continue

                    # found same resolved resource, both in 'self' stmt & 'other stmt
                    if method_on_stmt_actions_type == MethodOnStmtActionsType.DIFFERENCE:
                        result = resolved_action_single_stmt.difference(other_resolved_action_single_stmt)
                    elif method_on_stmt_actions_type == MethodOnStmtActionsType.INTERSECTION:
                        # for intersection, first needs to union all other stmts actions and do the intersection on that
                        resolved_actions_resource_for_intersection = (
                            resolved_actions_resources_for_intersection.setdefault(service_resource, set())
                        )
                        resolved_actions_resource_for_intersection.update(
                            other_resolved_action_single_stmt.resolved_stmt_actions
                        )
                        result = MethodOnStmtActionsResultType.APPLIED
                    else:
                        assert False  # should not get here, unknown enum value

                    res.resolved_stmt_results.add(
                        MethodOnStmtActionsResult(
                            resolved_single_stmt=other_resolved_stmt,
                            result=result,
                        )
                    )

            if method_on_stmt_actions_type == MethodOnStmtActionsType.INTERSECTION:
                # done aggregate all other stmts, possible now to intersects the results
                for service_resource, resolved_action_single_stmt in resolved_stmt.resolved_stmt_resources.items():
                    resolved_actions_resource: Optional[
                        Set[ServiceActionBase]
                    ] = resolved_actions_resources_for_intersection.get(service_resource)
                    if resolved_actions_resource:
                        resolved_action_single_stmt.resolved_stmt_actions.intersection_update(resolved_actions_resource)
                    else:
                        resolved_action_single_stmt.resolved_stmt_actions.clear()

            # remove all resolved resources which left with no resolved actions (after the method action)
            resolved_stmt.retain_resolved_stmt_resources()

        # remove all resolved stmts which left with no resolved resources (after the method action)
        self.retain_resolved_stmts()
        return res

    @classmethod
    @abstractmethod
    def load_from_single_stmt(
        cls, logger: Logger, stmt_ctx: StmtResourcesToResolveCtx, not_resource_annotated: bool
    ) -> 'ServiceResourcesResolverBase':
        pass

    def is_empty(self) -> bool:
        return len(self.get_resolved_stmts()) == 0

    def extend_resolved_stmts(self, resolved_single_stmt: List[ResolvedSingleStmtGetter]):
        self.get_resolved_stmts().extend(resolved_single_stmt)

    def yield_resolved_stmt_principals(
        self,
    ) -> Generator[PrincipalBase, None, None]:
        for resolved_stmt in self.yield_resolved_stmts():
            for resolved_stmt_principal in resolved_stmt.resolved_stmt_principals:
                yield resolved_stmt_principal

    def yield_resolved_resources(
        self,
        principal: Principal,
    ) -> Generator[ServiceResourceBase, None, None]:
        aggregate_resources: Set[ServiceResourceBase] = set()
        for resolved_stmt in self.yield_resolved_stmts():
            if not any(
                resolved_stmt_principal_base.get_principal().contains(principal)
                for resolved_stmt_principal_base in resolved_stmt.resolved_stmt_principals
            ):
                continue
            for resource in resolved_stmt.resolved_stmt_resources.keys():
                aggregate_resources.add(resource)

        for resource in aggregate_resources:
            yield resource

    def get_resolved_actions_per_resource_and_principal(
        self,
        service_resource: ServiceResourceBase,
        principal: Principal,
    ) -> Optional[Set[ServiceActionBase]]:
        aggregate_actions: Set[ServiceActionBase] = set()
        for resolved_stmt in self.yield_resolved_stmts():
            if not any(
                resolved_stmt_principal_base.get_principal().contains(principal)
                for resolved_stmt_principal_base in resolved_stmt.resolved_stmt_principals
            ):
                continue

            resolved_actions: Optional[ResolvedActionsSingleStmt] = resolved_stmt.resolved_stmt_resources.get(
                service_resource
            )
            if resolved_actions:
                aggregate_actions = aggregate_actions.union(resolved_actions.resolved_stmt_actions)

        return aggregate_actions if len(aggregate_actions) > 0 else None
