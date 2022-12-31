from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Type, Generator, Tuple

from serde import serde
from boto3 import Session

from authz_analyzer.datastores.aws.services.service_action_base import ServiceActionBase, ServiceActionType
from authz_analyzer.models.model import AssetType


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
    def get_asset_type(self) -> AssetType:
        pass

    @abstractmethod
    def __repr__(self):
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __hash__(self):
        pass


@dataclass
class ServiceResourcesResolverBase(ABC):
    @abstractmethod
    def is_empty(self) -> bool:
        pass

    @abstractmethod
    def yield_resolved_resource_with_actions(
        self,
    ) -> Generator[Tuple[ServiceResourceBase, Set[ServiceActionBase]], None, None]:
        pass

    @abstractmethod
    def add_from_single_stmt(self, other: 'ServiceResourcesResolverBase'):
        pass


@serde
class ServiceResourceType(ServiceActionType):
    @abstractmethod
    def get_resource_service_prefix(self) -> str:
        pass

    @classmethod
    @abstractmethod
    def load_resolver_service_resources_from_single_stmt(
        cls,
        logger: Logger,
        stmt_relative_id_regexes: List[str],
        service_resources: List[ServiceResourceBase],
        resolved_actions: Set[ServiceActionBase],
    ) -> ServiceResourcesResolverBase:
        pass

    @classmethod
    @abstractmethod
    def load_service_resources_from_session(cls, logger: Logger, session: Session) -> List[ServiceResourceBase]:
        pass
