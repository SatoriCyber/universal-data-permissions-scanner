from logging import Logger
from typing import Dict, List, Optional, Set, Type

from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.services import (
    ServiceActionBase,
    ServiceActionsResolverBase,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
    ServiceResourceType,
)
from aws_ptrp.services.assume_role.assume_role_actions import AssumeRoleAction, AssumeRoleServiceActionsResolver
from aws_ptrp.services.assume_role.assume_role_resources import AssumeRoleServiceResourcesResolver
from serde import serde

ROLE_TRUST_SERVICE_NAME = "role_trust_service"
ROLE_TRUST_ACTION_SERVICE_PREFIX = "sts:"
ROLE_TRUST_RESOURCE_SERVICE_PREFIX = "arn:aws:iam::"


@serde
class AssumeRoleService(ServiceResourceType):
    def get_service_name(self) -> str:
        return ROLE_TRUST_SERVICE_NAME

    def get_action_service_prefix(self) -> str:
        return ROLE_TRUST_ACTION_SERVICE_PREFIX

    def get_resource_service_prefix(self) -> str:
        return ROLE_TRUST_RESOURCE_SERVICE_PREFIX

    @classmethod
    def get_service_resources_resolver_type(cls) -> Type[ServiceResourcesResolverBase]:
        return AssumeRoleServiceResourcesResolver

    @classmethod
    def get_service_actions_resolver_type(cls) -> Type[ServiceActionsResolverBase]:
        return AssumeRoleServiceActionsResolver

    @classmethod
    def load_service_actions(cls, logger: Logger) -> List[ServiceActionBase]:
        return AssumeRoleAction.load_role_trust_actions(logger)

    @classmethod
    def load_service_resources(
        cls,
        _logger: Logger,
        _resources_loaded_from_session: Dict['ServiceResourceType', Set[ServiceResourceBase]],
        iam_entities: IAMEntities,
    ) -> Optional[Set[ServiceResourceBase]]:
        return set([x for x in iam_entities.iam_roles.values()])
