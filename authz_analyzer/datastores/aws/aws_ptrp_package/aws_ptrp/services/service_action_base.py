import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Type

from aws_ptrp.iam.policy.policy_document_utils import fix_stmt_regex_to_valid_regex
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpActionPermissionLevel
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
@dataclass
class ServiceActionBase(ABC):
    @abstractmethod
    def get_action_name(self) -> str:
        pass

    @abstractmethod
    def get_action_permission_level(self) -> AwsPtrpActionPermissionLevel:
        pass


@dataclass
class ResolvedActionsSingleStmt(ABC):
    @property
    @abstractmethod
    def resolved_stmt_actions(self) -> Set[ServiceActionBase]:
        pass

    @abstractmethod
    def subtract(self, other: 'ResolvedActionsSingleStmt'):
        pass


@dataclass
class ServiceActionsResolverBase(ABC):
    @abstractmethod
    def get_resolved_actions(self) -> Set[ServiceActionBase]:
        pass

    def is_empty(self) -> bool:
        return len(self.get_resolved_actions()) == 0

    @classmethod
    @abstractmethod
    def load_from_single_stmt(
        cls, logger: Logger, stmt_regexes: List[str], service_actions: List[ServiceActionBase]
    ) -> 'ServiceActionsResolverBase':
        pass

    @staticmethod
    def resolve_actions_from_single_stmt_regex(
        stmt_regex: str, service_actions: List[ServiceActionBase]
    ) -> Set[ServiceActionBase]:
        # actions are case insensitive
        regex = re.compile(fix_stmt_regex_to_valid_regex(stmt_regex, with_case_sensitive=False))
        service_actions_matches: List[ServiceActionBase] = [
            s for s in service_actions if regex.match(s.get_action_name()) is not None
        ]
        return set(service_actions_matches)

    @staticmethod
    def resolve_actions_from_single_stmt_regexes(
        stmt_regexes: List[str], service_actions: List[ServiceActionBase]
    ) -> Set[ServiceActionBase]:
        resolved_actions: Set[ServiceActionBase] = set()
        for stmt_regex in stmt_regexes:
            resolved_actions = resolved_actions.union(
                ServiceActionsResolverBase.resolve_actions_from_single_stmt_regex(stmt_regex, service_actions)
            )
        return resolved_actions


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
    def load_service_actions(cls, logger: Logger) -> List[ServiceActionBase]:
        pass

    @classmethod
    def load_resolver_service_actions_from_single_stmt(
        cls, logger: Logger, stmt_relative_id_regexes: List[str], service_actions: List[ServiceActionBase]
    ) -> ServiceActionsResolverBase:
        return cls.get_service_actions_resolver_type().load_from_single_stmt(
            logger, stmt_relative_id_regexes, service_actions
        )
