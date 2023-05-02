from dataclasses import dataclass
from enum import Enum, auto
from logging import Logger
from typing import List, Set

from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpActionPermissionLevel
from aws_ptrp.services import ServiceActionBase, ServiceActionsResolverBase
from aws_ptrp.utils.serde import serde_enum_field
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
    is_assumed_role: bool
    action_type: AssumeRoleActionType = serde_enum_field(AssumeRoleActionType)
    permission_level: AwsPtrpActionPermissionLevel = serde_enum_field(AwsPtrpActionPermissionLevel)

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
    def load_role_trust_actions(cls, _logger: Logger) -> Set[ServiceActionBase]:
        return role_trust_actions


@dataclass
class AssumeRoleServiceActionsResolver(ServiceActionsResolverBase):
    resolved_actions: Set[AssumeRoleAction]

    def get_resolved_actions(self) -> Set[ServiceActionBase]:
        return self.resolved_actions  # type: ignore[return-value]

    @classmethod
    def load_from_single_stmt(
        cls,
        _logger: Logger,
        stmt_regexes: List[str],
        service_actions: Set[ServiceActionBase],
        not_action_annotated: bool,
    ) -> 'ServiceActionsResolverBase':
        resolved_actions = ServiceActionsResolverBase.resolve_actions_from_single_stmt_regexes(
            stmt_regexes, service_actions, not_action_annotated
        )
        resolved_assume_actions: Set[AssumeRoleAction] = set(
            [s for s in resolved_actions if isinstance(s, AssumeRoleAction)]
        )
        return cls(resolved_actions=resolved_assume_actions)


role_trust_actions: Set[ServiceActionBase] = {
    AssumeRoleAction("AssumeRole", True, AssumeRoleActionType.ASSUME_ROLE, AwsPtrpActionPermissionLevel.FULL),
    AssumeRoleAction(
        "AssumeRoleWithWebIdentity",
        True,
        AssumeRoleActionType.ASSUME_ROLE_WITH_WEB_IDENTITY,
        AwsPtrpActionPermissionLevel.FULL,
    ),
    AssumeRoleAction(
        "AssumeRoleWithSAML", True, AssumeRoleActionType.ASSUME_ROLE_WITH_SAML, AwsPtrpActionPermissionLevel.FULL
    ),
    AssumeRoleAction("TagSession", False, AssumeRoleActionType.TAG_SESSION, AwsPtrpActionPermissionLevel.FULL),
    AssumeRoleAction("TagSession", False, AssumeRoleActionType.SET_SOURCE_IDENTITY, AwsPtrpActionPermissionLevel.FULL),
}
