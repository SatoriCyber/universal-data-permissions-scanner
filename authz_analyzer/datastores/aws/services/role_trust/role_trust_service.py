from logging import Logger
from typing import List

from serde import serde

from authz_analyzer.datastores.aws.services.role_trust.role_trust_actions import (
    RoleTrustAction,
    RoleTrustServiceActionsResolver,
)
from authz_analyzer.datastores.aws.services import (
    ServiceActionBase,
    ServiceActionsResolverBase,
    ServiceActionType,
)

ROLE_TRUST_SERVICE_NAME = "role_trust"


@serde
class RoleTrustServiceType(ServiceActionType):
    def get_action_service_prefix(self) -> str:
        return "sts:"

    def get_service_name(self) -> str:
        return ROLE_TRUST_SERVICE_NAME

    @classmethod
    def load_resolver_service_actions_from_single_stmt(
        cls, logger: Logger, stmt_relative_id_regexes: List[str], service_actions: List[ServiceActionBase]
    ) -> ServiceActionsResolverBase:
        role_trust_actions: List[RoleTrustAction] = [s for s in service_actions if isinstance(s, RoleTrustAction)]
        return RoleTrustServiceActionsResolver.load(logger, stmt_relative_id_regexes, role_trust_actions)

    @classmethod
    def load_service_actions(cls, logger: Logger) -> List[ServiceActionBase]:
        return RoleTrustAction.load_role_trust_actions(logger)
