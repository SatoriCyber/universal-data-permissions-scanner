from typing import Dict, Any, Optional, Type, List, Union, Tuple, AnyStr, Set, Type
from abc import ABC, abstractmethod
from dataclasses import dataclass
from boto3 import Session
from logging import Logger
from serde import serde
from authz_analyzer.datastores.aws.iam.policy.resolve_service_entities_base import ResolvedServiceEntitiesBase


@serde
@dataclass
class ServiceEntityBase(ABC):
    @abstractmethod
    def get_entity_arn(self) -> str:
        pass

    @abstractmethod
    def get_entity_name(self) -> str:
        pass


@serde
class ServiceType(ABC):
    @abstractmethod
    def get_service_prefix(self) -> str:
        pass

    @abstractmethod
    def get_service_name(self) -> str:
        pass

    @classmethod
    @abstractmethod
    def load_resolver_service_entities(
        cls, logger: Logger, stmt_relative_id_regex: str, service_entities: List[ServiceEntityBase]
    ) -> ResolvedServiceEntitiesBase:
        pass

    @classmethod
    @abstractmethod
    def load_service_entities_from_session(cls, logger: Logger, session: Session) -> List[ServiceEntityBase]:
        pass

    def __repr__(self):
        return self.get_service_name()

    def __eq__(self, other):
        return self.get_service_name() == other.get_service_name()

    def __hash__(self):
        return hash(self.get_service_name())
