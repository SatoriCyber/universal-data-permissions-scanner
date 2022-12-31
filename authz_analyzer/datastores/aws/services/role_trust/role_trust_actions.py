import re
from dataclasses import dataclass
from enum import Enum, auto
from logging import Logger
from typing import List, Set

from serde import serde

from authz_analyzer.datastores.aws.iam.policy.policy_document_utils import fix_stmt_regex_to_valid_regex
from authz_analyzer.datastores.aws.services.service_action_base import ServiceActionBase, ServiceActionsResolverBase
from authz_analyzer.models import PermissionLevel


class RoleTrustActionType(Enum):
    ASSUME_ROLE = auto()
    ASSUME_ROLE_WITH_SAML = auto()
    ASSUME_ROLE_WITH_WEB_IDENTITY = auto()
    TAG_SESSION = auto()
    SET_SOURCE_IDENTITY = auto()


@serde
@dataclass
class RoleTrustAction(ServiceActionBase):
    name: str
    action_type: RoleTrustActionType
    permission_level: PermissionLevel
    is_assumed_role: bool

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def get_action_name(self) -> str:
        return self.name

    def get_action_permission_level(self) -> PermissionLevel:
        return self.permission_level

    @classmethod
    def get_relevant_actions_for_assumed_type(
        cls, logger: Logger, assumed_type: RoleTrustActionType
    ) -> List['RoleTrustAction']:
        all_actions = RoleTrustAction.load_role_trust_actions(logger)
        return [
            action
            for action in all_actions
            if isinstance(action, RoleTrustAction)
            and (not action.is_assumed_role or action.action_type == assumed_type)
        ]

    @classmethod
    def load_role_trust_actions(cls, _logger: Logger) -> List[ServiceActionBase]:
        return role_trust_actions


@dataclass
class RoleTrustServiceActionsResolver(ServiceActionsResolverBase):
    resolved_actions: Set[RoleTrustAction]

    def is_empty(self) -> bool:
        return len(self.resolved_actions) == 0

    def get_resolved_actions(self) -> Set[ServiceActionBase]:
        return self.resolved_actions  # type: ignore[return-value]

    @staticmethod
    def resolve_actions(stmt_regex: str, service_actions: List[RoleTrustAction]) -> Set[RoleTrustAction]:
        # actions are case insensitive
        regex = re.compile(fix_stmt_regex_to_valid_regex(stmt_regex, with_case_insensitive=True))
        service_actions_matches: List[RoleTrustAction] = [
            s for s in service_actions if regex.match(s.get_action_name()) is not None
        ]
        return set(service_actions_matches)

    @classmethod
    def load(
        cls, _logger: Logger, stmt_regexes: List[str], service_actions: List[RoleTrustAction]
    ) -> 'ServiceActionsResolverBase':
        resolved_actions: Set[RoleTrustAction] = set()
        for stmt_regex in stmt_regexes:
            resolved_actions = resolved_actions.union(
                RoleTrustServiceActionsResolver.resolve_actions(stmt_regex, service_actions)
            )

        return cls(
            resolved_actions=resolved_actions,
        )


role_trust_actions: List[ServiceActionBase] = [
    RoleTrustAction("AssumeRole", RoleTrustActionType.ASSUME_ROLE, PermissionLevel.FULL, True),
    RoleTrustAction(
        "AssumeRoleWithWebIdentity", RoleTrustActionType.ASSUME_ROLE_WITH_WEB_IDENTITY, PermissionLevel.FULL, True
    ),
    RoleTrustAction("AssumeRoleWithSAML", RoleTrustActionType.ASSUME_ROLE_WITH_SAML, PermissionLevel.FULL, True),
    RoleTrustAction("TagSession", RoleTrustActionType.TAG_SESSION, PermissionLevel.FULL, False),
    RoleTrustAction("TagSession", RoleTrustActionType.SET_SOURCE_IDENTITY, PermissionLevel.FULL, False),
]
