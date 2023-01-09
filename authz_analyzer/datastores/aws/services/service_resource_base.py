from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Type, Generator
from serde import serde
from boto3 import Session

from authz_analyzer.datastores.aws.services.service_action_base import (
    ServiceActionBase,
    ServiceActionType,
    ResolvedActionsSingleStmt,
)
from authz_analyzer.datastores.aws.iam.policy.principal import StmtPrincipal


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


@dataclass
class ResolvedResourcesSingleStmt(ABC):
    @property
    @abstractmethod
    def resolved_stmt_principals(self) -> List[StmtPrincipal]:
        pass

    @property
    @abstractmethod
    def resolved_stmt_resources(self) -> Dict[ServiceResourceBase, ResolvedActionsSingleStmt]:
        pass


@dataclass
class ServiceResourcesResolverBase(ABC):
    @abstractmethod
    def get_resolved_stmts(self) -> List[ResolvedResourcesSingleStmt]:
        pass

    @abstractmethod
    def subtract(self, other: 'ServiceResourcesResolverBase'):
        pass

    @classmethod
    @abstractmethod
    def load_from_single_stmt(
        cls,
        logger: Logger,
        stmt_relative_id_regexes: List[str],
        service_resources: Set[ServiceResourceBase],
        resolved_stmt_principals: List[StmtPrincipal],
        resolved_stmt_actions: Set[ServiceActionBase],
    ) -> 'ServiceResourcesResolverBase':
        pass

    def is_empty(self) -> bool:
        return len(self.get_resolved_stmts()) == 0

    def extend_resolved_stmts(self, resolved_single_stmt: List[ResolvedResourcesSingleStmt]):
        self.get_resolved_stmts().extend(resolved_single_stmt)

    def yield_resolved_stmt_principals(
        self,
    ) -> Generator[StmtPrincipal, None, None]:
        for resolved_stmt in self.get_resolved_stmts():
            for resolved_stmt_principal in resolved_stmt.resolved_stmt_principals:
                yield resolved_stmt_principal

    def yield_resolved_resources(
        self,
        principal: StmtPrincipal,
    ) -> Generator[ServiceResourceBase, None, None]:
        aggregate_resources: Set[ServiceResourceBase] = set()
        for resolved_stmt in self.get_resolved_stmts():
            if not any(
                principal.contains(resolved_stmt_principal)
                for resolved_stmt_principal in resolved_stmt.resolved_stmt_principals
            ):
                continue
            for resource in resolved_stmt.resolved_stmt_resources.keys():
                aggregate_resources.add(resource)

        for resource in aggregate_resources:
            yield resource

    def get_resolved_actions(
        self,
        service_resource: ServiceResourceBase,
        principal: StmtPrincipal,
    ) -> Optional[Set[ServiceActionBase]]:
        aggregate_actions: Set[ServiceActionBase] = set()
        for resolved_stmt in self.get_resolved_stmts():
            if not any(
                principal.contains(resolved_stmt_principal)
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
        resolved_stmt_principals: List[StmtPrincipal],
        resolved_stmt_actions: Set[ServiceActionBase],
    ) -> ServiceResourcesResolverBase:
        return cls.get_service_resources_resolver_type().load_from_single_stmt(
            logger, stmt_relative_id_regexes, service_resources, resolved_stmt_principals, resolved_stmt_actions
        )

    @classmethod
    @abstractmethod
    def load_service_resources(cls, logger: Logger, session: Session, iam_entities) -> Set[ServiceResourceBase]:
        pass
