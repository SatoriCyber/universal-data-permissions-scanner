from dataclasses import dataclass
from enum import Enum, auto
from logging import Logger
from typing import List, Set

from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpActionPermissionLevel
from aws_ptrp.services import ServiceActionBase, ServiceActionsResolverBase
from serde import serde


class AssumeRoleActionType(Enum):
    ASSUME_ROLE = auto()
    ASSUME_ROLE_WITH_SAML = auto()
    ASSUME_ROLE_WITH_WEB_IDENTITY = auto()
    TAG_SESSION = auto()
    SET_SOURCE_IDENTITY = auto()


@serde
@dataclass
class AssumeRoleAction(ServiceActionBase):
    name: str
    action_type: AssumeRoleActionType
    permission_level: AwsPtrpActionPermissionLevel
    is_assumed_role: bool

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def get_action_name(self) -> str:
        return self.name

    def get_action_permission_level(self) -> AwsPtrpActionPermissionLevel:
        return self.permission_level

    @classmethod
    def load_role_trust_actions(cls, _logger: Logger) -> List[ServiceActionBase]:
        return role_trust_actions


@dataclass
class AssumeRoleServiceActionsResolver(ServiceActionsResolverBase):
    resolved_actions: Set[AssumeRoleAction]

    def get_resolved_actions(self) -> Set[ServiceActionBase]:
        return self.resolved_actions  # type: ignore[return-value]

    @classmethod
    def load_from_single_stmt(
        cls, _logger: Logger, stmt_regexes: List[str], service_actions: List[ServiceActionBase]
    ) -> 'ServiceActionsResolverBase':
        resolved_actions = ServiceActionsResolverBase.resolve_actions_from_single_stmt_regexes(
            stmt_regexes, service_actions
        )
        resolved_assume_actions: Set[AssumeRoleAction] = set(
            [s for s in resolved_actions if isinstance(s, AssumeRoleAction)]
        )
        return cls(resolved_actions=resolved_assume_actions)


role_trust_actions: List[ServiceActionBase] = [
    AssumeRoleAction("AssumeRole", AssumeRoleActionType.ASSUME_ROLE, AwsPtrpActionPermissionLevel.FULL, True),
    AssumeRoleAction(
        "AssumeRoleWithWebIdentity",
        AssumeRoleActionType.ASSUME_ROLE_WITH_WEB_IDENTITY,
        AwsPtrpActionPermissionLevel.FULL,
        True,
    ),
    AssumeRoleAction(
        "AssumeRoleWithSAML", AssumeRoleActionType.ASSUME_ROLE_WITH_SAML, AwsPtrpActionPermissionLevel.FULL, True
    ),
    AssumeRoleAction("TagSession", AssumeRoleActionType.TAG_SESSION, AwsPtrpActionPermissionLevel.FULL, False),
    AssumeRoleAction("TagSession", AssumeRoleActionType.SET_SOURCE_IDENTITY, AwsPtrpActionPermissionLevel.FULL, False),
]
