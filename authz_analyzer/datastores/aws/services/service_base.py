from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import List

from boto3 import Session
from serde import serde

from authz_analyzer.datastores.aws.actions.service_actions_resolver_base import ServiceActionsResolverBase
from authz_analyzer.datastores.aws.resources.service_resources_resolver_base import ServiceResourcesResolverBase
from authz_analyzer.models import PermissionLevel


@serde
@dataclass
class ServiceActionBase(ABC):
    @abstractmethod
    def get_action_name(self) -> str:
        pass

    @abstractmethod
    def get_action_permission_level(self) -> PermissionLevel:
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
        cls, logger: Logger, stmt_relative_id_regex: str, service_resources: List[ServiceResourceBase]
    ) -> ServiceResourcesResolverBase:
        pass

    @classmethod
    @abstractmethod
    def load_service_resources_from_session(cls, logger: Logger, session: Session) -> List[ServiceResourceBase]:
        pass

    @classmethod
    @abstractmethod
    def load_resolver_service_actions(
        cls, logger: Logger, stmt_relative_id_regex: str, service_actions: List[ServiceActionBase]
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
