from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Set, Type, List
from logging import Logger
from serde import serde

from authz_analyzer.models.model import PermissionLevel
from authz_analyzer.datastores.aws.services.service_base import ServiceType


_SERVICE_ACTION_TYPE_BY_NAME: Dict[str, Type['ServiceActionType']] = dict()


def register_service_action_type_by_name(service_name: str, service_type: Type['ServiceActionType']):
    _SERVICE_ACTION_TYPE_BY_NAME[service_name] = service_type


def get_service_action_type_by_name(service_name: str) -> Optional[Type['ServiceActionType']]:
    return _SERVICE_ACTION_TYPE_BY_NAME.get(service_name, None)


_SERVICE_ACTION_BY_NAME: Dict[str, Type['ServiceActionBase']] = dict()


def register_service_action_by_name(service_name: str, service_action: Type['ServiceActionBase']):
    _SERVICE_ACTION_BY_NAME[service_name] = service_action


def get_service_action_by_name(service_name: str) -> Optional[Type['ServiceActionBase']]:
    return _SERVICE_ACTION_BY_NAME.get(service_name, None)


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

    @abstractmethod
    def get_resolved_actions(self) -> Set[ServiceActionBase]:
        pass


@serde
class ServiceActionType(ServiceType):
    @abstractmethod
    def get_action_service_prefix(self) -> str:
        pass

    @classmethod
    @abstractmethod
    def load_resolver_service_actions_from_single_stmt(
        cls, logger: Logger, stmt_relative_id_regexes: List[str], service_actions: List[ServiceActionBase]
    ) -> ServiceActionsResolverBase:
        pass

    @classmethod
    @abstractmethod
    def load_service_actions(cls, logger: Logger) -> List[ServiceActionBase]:
        pass
