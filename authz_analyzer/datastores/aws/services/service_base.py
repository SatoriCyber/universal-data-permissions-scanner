from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Type

from boto3 import Session
from serde import serde

from authz_analyzer.models.model import AssetType, PermissionLevel

_SERVICE_TYPE_BY_NAME: Dict[str, Type['ServiceType']] = dict()


def register_service_type_by_name(service_name: str, service_type: Type['ServiceType']):
    _SERVICE_TYPE_BY_NAME[service_name] = service_type


def get_service_type_by_name(service_name: str) -> Optional[Type['ServiceType']]:
    return _SERVICE_TYPE_BY_NAME.get(service_name, None)


_SERVICE_ACTION_BY_NAME: Dict[str, Type['ServiceActionBase']] = dict()


def register_service_action_by_name(service_name: str, service_action: Type['ServiceActionBase']):
    _SERVICE_ACTION_BY_NAME[service_name] = service_action


def get_service_action_by_name(service_name: str) -> Optional[Type['ServiceActionBase']]:
    return _SERVICE_ACTION_BY_NAME.get(service_name, None)


_SERVICE_RESOURCE_BY_NAME: Dict[str, Type['ServiceResourceBase']] = dict()


def register_service_resource_by_name(service_name: str, service_action: Type['ServiceResourceBase']):
    _SERVICE_RESOURCE_BY_NAME[service_name] = service_action


def get_service_resource_by_name(service_name: str) -> Optional[Type['ServiceResourceBase']]:
    return _SERVICE_RESOURCE_BY_NAME.get(service_name, None)


@serde
@dataclass
class ServiceActionBase(ABC):
    @abstractmethod
    def get_action_name(self) -> str:
        pass

    @abstractmethod
    def get_action_permission_level(self) -> PermissionLevel:
        pass


@dataclass
class ServiceActionsResolverBase(ABC):
    @abstractmethod
    def is_empty(self) -> bool:
        pass

    # @abstractmethod
    # def subtraction_actions(self, other: 'ServiceActionsResolverBase'):
    #     pass

    @abstractmethod
    def get_resolved_actions(self) -> Set[ServiceActionBase]:
        pass


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

    # @abstractmethod
    # def subtraction_entities_for_actions(self, other: 'ServiceResourcesResolverBase', actions):
    #     pass

    @abstractmethod
    def get_resolved_resources(self) -> Dict[ServiceResourceBase, Set[ServiceActionBase]]:
        pass

    @abstractmethod
    def merge(self, other: 'ServiceResourcesResolverBase'):
        pass


@serde
class ServiceType(ABC):
    @abstractmethod
    def get_resource_service_prefix(self) -> str:
        pass

    @abstractmethod
    def get_action_service_prefix(self) -> str:
        pass

    @abstractmethod
    def get_service_name(self) -> str:
        pass

    @classmethod
    @abstractmethod
    def load_resolver_service_resources(
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

    @classmethod
    @abstractmethod
    def load_resolver_service_actions(
        cls, logger: Logger, stmt_relative_id_regexes: List[str], service_actions: List[ServiceActionBase]
    ) -> ServiceActionsResolverBase:
        pass

    @classmethod
    @abstractmethod
    def load_service_actions(cls, logger: Logger) -> List[ServiceActionBase]:
        pass

    def __repr__(self):
        return self.get_service_name()

    def __eq__(self, other):
        return self.get_service_name() == other.get_service_name()

    def __hash__(self):
        return hash(self.get_service_name())
