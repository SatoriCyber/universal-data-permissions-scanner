from dataclasses import dataclass
from logging import Logger
from typing import List, Set

from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpActionPermissionLevel
from aws_ptrp.services.service_action_base import ServiceActionBase, ServiceActionsResolverBase
from serde import serde


@serde
@dataclass
class FederatedUserAction(ServiceActionBase):
    name: str
    permission_level: AwsPtrpActionPermissionLevel

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
    def load_federated_user_actions(cls, _logger: Logger) -> List[ServiceActionBase]:
        return federated_user_actions


@dataclass
class FederatedUserServiceActionsResolver(ServiceActionsResolverBase):
    resolved_actions: Set[FederatedUserAction]

    def get_resolved_actions(self) -> Set[ServiceActionBase]:
        return self.resolved_actions  # type: ignore[return-value]

    @classmethod
    def load_from_single_stmt(
        cls, _logger: Logger, stmt_regexes: List[str], service_actions: List[ServiceActionBase]
    ) -> 'ServiceActionsResolverBase':
        resolved_actions = ServiceActionsResolverBase.resolve_actions_from_single_stmt_regexes(
            stmt_regexes, service_actions
        )
        resolved_federated_user_actions: Set[FederatedUserAction] = set(
            [s for s in resolved_actions if isinstance(s, FederatedUserAction)]
        )
        return cls(resolved_actions=resolved_federated_user_actions)


federated_user_actions: List[ServiceActionBase] = [
    FederatedUserAction("GetFederationToken", AwsPtrpActionPermissionLevel.FULL),
]
