from abc import abstractmethod
from logging import Logger
from typing import Dict, List, Optional, Set, Type

from aws_ptrp.services.service_action_base import ServiceActionBase
from aws_ptrp.services.service_actions_resolver_base import ServiceActionsResolverBase
from aws_ptrp.services.service_base import ServiceType
from serde import serde

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
class ServiceActionType(ServiceType):
    @abstractmethod
    def get_action_service_prefix(self) -> str:
        pass

    @classmethod
    @abstractmethod
    def get_service_actions_resolver_type(cls) -> Type[ServiceActionsResolverBase]:
        pass

    @classmethod
    @abstractmethod
    def load_service_actions(cls, logger: Logger) -> Set[ServiceActionBase]:
        pass

    @classmethod
    def load_resolver_service_actions_from_single_stmt(
        cls,
        logger: Logger,
        stmt_relative_id_regexes: List[str],
        service_actions: Set[ServiceActionBase],
        not_action_annotated: bool,
    ) -> ServiceActionsResolverBase:
        return cls.get_service_actions_resolver_type().load_from_single_stmt(
            logger, stmt_relative_id_regexes, service_actions, not_action_annotated
        )
