import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import List, Set

from aws_ptrp.iam.policy.policy_document_utils import fix_stmt_regex_to_valid_regex
from aws_ptrp.services.service_action_base import ServiceActionBase


@dataclass
class ResolvedActionsSingleStmt(ABC):
    @property
    @abstractmethod
    def resolved_stmt_actions(self) -> Set[ServiceActionBase]:
        pass

    def difference(self, other: 'ResolvedActionsSingleStmt'):
        self.resolved_stmt_actions.difference_update(other.resolved_stmt_actions)

    def intersection(self, other: 'ResolvedActionsSingleStmt'):
        self.resolved_stmt_actions.intersection_update(other.resolved_stmt_actions)


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
        cls,
        logger: Logger,
        stmt_regexes: List[str],
        service_actions: Set[ServiceActionBase],
        not_action_annotated: bool,
    ) -> 'ServiceActionsResolverBase':
        pass

    @staticmethod
    def resolve_actions_from_single_stmt_regex(
        stmt_regex: str, service_actions: Set[ServiceActionBase]
    ) -> Set[ServiceActionBase]:
        # actions are case insensitive
        regex = re.compile(fix_stmt_regex_to_valid_regex(stmt_regex, with_case_sensitive=False))
        return set([s for s in service_actions if regex.match(s.get_action_name()) is not None])

    @staticmethod
    def resolve_actions_from_single_stmt_regexes(
        stmt_regexes: List[str], service_actions: Set[ServiceActionBase], not_action_annotated: bool
    ) -> Set[ServiceActionBase]:
        resolved_actions: Set[ServiceActionBase] = set()
        for stmt_regex in stmt_regexes:
            resolved_actions = resolved_actions.union(
                ServiceActionsResolverBase.resolve_actions_from_single_stmt_regex(stmt_regex, service_actions)
            )
        if not_action_annotated:
            resolved_actions = service_actions.difference(resolved_actions)
        return resolved_actions
