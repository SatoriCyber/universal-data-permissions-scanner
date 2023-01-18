from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import Dict, Generator, List, Optional, Set, Type

from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.principals import Principal
from aws_ptrp.services.service_action_base import ResolvedActionsSingleStmt, ServiceActionBase, ServiceActionType
from boto3 import Session
from serde import serde

_SERVICE_RESOURCE_TYPE_BY_NAME: Dict[str, Type['ServiceResourceType']] = dict()


def register_service_resource_type_by_name(service_name: str, service_type: Type['ServiceResourceType']):
    _SERVICE_RESOURCE_TYPE_BY_NAME[service_name] = service_type


def get_service_resource_type_by_name(service_name: str) -> Optional[Type['ServiceResourceType']]:
    return _SERVICE_RESOURCE_TYPE_BY_NAME.get(service_name, None)


_SERVICE_RESOURCE_BY_NAME: Dict[str, Type['ServiceResourceBase']] = dict()


def register_service_resource_by_name(service_name: str, service_action: Type['ServiceResourceBase']):
    _SERVICE_RESOURCE_BY_NAME[service_name] = service_action


def get_service_resource_by_name(service_name: str) -> Optional[Type['ServiceResourceBase']]:
    return _SERVICE_RESOURCE_BY_NAME.get(service_name, None)


@serde
@dataclass
class ServiceResourceBase(ABC):
    @abstractmethod
    def get_resource_arn(self) -> str:
        pass

    @abstractmethod
    def get_resource_name(self) -> str:
        pass

    @abstractmethod
    def get_resource_policy(self) -> Optional[PolicyDocument]:
        pass

    @abstractmethod
    def get_resource_account_id(self) -> str:
        pass


@dataclass
class ResolvedResourcesSingleStmt(ABC):
    @property
    @abstractmethod
    def resolved_stmt_principals(self) -> List[Principal]:
        pass

    @property
    @abstractmethod
    def resolved_stmt_resources(self) -> Dict[ServiceResourceBase, ResolvedActionsSingleStmt]:
        pass

    def retain_resolved_stmt_resources(self):
        # get all service resources with empty resolved stmt actions
        service_resources_to_delete = [
            x[0] for x in self.resolved_stmt_resources.items() if not x[1].resolved_stmt_actions
        ]
        # delete all these keys from the resolved_stmt_resources
        for service_resource_to_delete in service_resources_to_delete:
            del self.resolved_stmt_resources[service_resource_to_delete]


@dataclass
class ServiceResourcesResolverBase(ABC):
    @abstractmethod
    def get_resolved_stmts(self) -> List[ResolvedResourcesSingleStmt]:
        pass

    def retain_resolved_stmts(self):
        # get all list indexes to delete (single stmt with empty resolved actions)
        stmt_indexes_to_delete = []
        curr_index = 0
        resolved_stmts: List[ResolvedResourcesSingleStmt] = self.get_resolved_stmts()
        for resolved_stmt in resolved_stmts:
            if not resolved_stmt.resolved_stmt_resources:
                stmt_indexes_to_delete.append(curr_index)
            curr_index = curr_index + 1

        element_deleted = 0
        for stmt_index_to_delete in stmt_indexes_to_delete:
            del resolved_stmts[stmt_index_to_delete - element_deleted]
            element_deleted = element_deleted + 1

    def subtract(self, principal: Principal, other: 'ServiceResourcesResolverBase'):
        '''subtract resolved actions from 'self' statements with 'other' statement.
        For each statement in self & other which contains the principal, subtract the resolved actions for each resolved resource
        '''
        for resolved_stmt in self.get_resolved_stmts():
            if not any(
                resolved_stmt_principal.contains(principal)
                for resolved_stmt_principal in resolved_stmt.resolved_stmt_principals
            ):
                continue
            # self stmt relevant to this principal
            for other_resolved_stmt in other.get_resolved_stmts():
                if not any(
                    other_resolved_stmt_principal.contains(principal)
                    for other_resolved_stmt_principal in other_resolved_stmt.resolved_stmt_principals
                ):
                    continue
                # other stmt relevant to this principal
                # Need to check matches on the resolved resources in these statements
                for service_resource, resolved_action_single_stmt in resolved_stmt.resolved_stmt_resources.items():
                    other_resolved_action_single_stmt: Optional[
                        ResolvedActionsSingleStmt
                    ] = other_resolved_stmt.resolved_stmt_resources.get(service_resource)

                    if not other_resolved_action_single_stmt:
                        continue
                    # found same resolved resource, both in 'self' stmt & 'other stmt
                    # subtract the resolved action
                    resolved_action_single_stmt.subtract(other_resolved_action_single_stmt)

            # remove all resolved resources which left with no resolved actions (after the subtraction)
            resolved_stmt.retain_resolved_stmt_resources()

        # remove all resolved stmts which left with no resolved resources (after the subtraction)
        self.retain_resolved_stmts()

    @classmethod
    @abstractmethod
    def load_from_single_stmt(
        cls,
        logger: Logger,
        stmt_relative_id_regexes: List[str],
        service_resources: Set[ServiceResourceBase],
        resolved_stmt_principals: List[Principal],
        resolved_stmt_actions: Set[ServiceActionBase],
    ) -> 'ServiceResourcesResolverBase':
        pass

    def is_empty(self) -> bool:
        return len(self.get_resolved_stmts()) == 0

    def extend_resolved_stmts(self, resolved_single_stmt: List[ResolvedResourcesSingleStmt]):
        self.get_resolved_stmts().extend(resolved_single_stmt)

    def yield_resolved_stmt_principals(
        self,
    ) -> Generator[Principal, None, None]:
        for resolved_stmt in self.get_resolved_stmts():
            for resolved_stmt_principal in resolved_stmt.resolved_stmt_principals:
                yield resolved_stmt_principal

    def yield_resolved_resources(
        self,
        principal: Principal,
    ) -> Generator[ServiceResourceBase, None, None]:
        aggregate_resources: Set[ServiceResourceBase] = set()
        for resolved_stmt in self.get_resolved_stmts():
            if not any(
                resolved_stmt_principal.contains(principal)
                for resolved_stmt_principal in resolved_stmt.resolved_stmt_principals
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
        for resolved_stmt in self.get_resolved_stmts():
            if not any(
                resolved_stmt_principal.contains(principal)
                for resolved_stmt_principal in resolved_stmt.resolved_stmt_principals
            ):
                continue

            resolved_actions: Optional[ResolvedActionsSingleStmt] = resolved_stmt.resolved_stmt_resources.get(
                service_resource
            )
            if resolved_actions:
                aggregate_actions = aggregate_actions.union(resolved_actions.resolved_stmt_actions)

        return aggregate_actions if len(aggregate_actions) > 0 else None


@serde
class ServiceResourceType(ServiceActionType):
    @abstractmethod
    def get_resource_service_prefix(self) -> str:
        pass

    @classmethod
    @abstractmethod
    def get_service_resources_resolver_type(cls) -> Type[ServiceResourcesResolverBase]:
        pass

    @classmethod
    def load_resolver_service_resources_from_single_stmt(
        cls,
        logger: Logger,
        stmt_relative_id_regexes: List[str],
        service_resources: Set[ServiceResourceBase],
        resolved_stmt_principals: List[Principal],
        resolved_stmt_actions: Set[ServiceActionBase],
    ) -> ServiceResourcesResolverBase:
        return cls.get_service_resources_resolver_type().load_from_single_stmt(
            logger, stmt_relative_id_regexes, service_resources, resolved_stmt_principals, resolved_stmt_actions
        )

    @classmethod
    def load_service_resources_from_session(
        cls, _logger: Logger, _session: Session, _aws_account_id: str
    ) -> Optional[Set[ServiceResourceBase]]:
        return None

    @classmethod
    def load_service_resources(
        cls,
        _logger: Logger,
        _resources_loaded_from_session: Dict['ServiceResourceType', Set[ServiceResourceBase]],
        _iam_entities,
    ) -> Optional[Set[ServiceResourceBase]]:
        return None
