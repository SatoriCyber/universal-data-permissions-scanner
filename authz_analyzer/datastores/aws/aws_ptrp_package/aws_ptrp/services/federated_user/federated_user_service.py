from logging import Logger
from typing import Optional, Set, Type

from aws_ptrp.ptrp_models import AwsPrincipalType
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import (
    ServiceActionBase,
    ServiceActionsResolverBase,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
    ServiceResourceType,
)
from aws_ptrp.services.federated_user.federated_user_actions import (
    FederatedUserAction,
    FederatedUserServiceActionsResolver,
)
from aws_ptrp.services.federated_user.federated_user_resources import (
    FederatedUserResource,
    FederatedUserServiceResourcesResolver,
)
from serde import serde

FEDERATED_USER_SERVICE_NAME = "federated user"
FEDERATED_USER_ACTION_SERVICE_PREFIX = "sts:"
FEDERATED_USER_RESOURCE_SERVICE_PREFIX = "arn:aws:sts::"


@serde
class FederatedUserService(ServiceResourceType):
    def get_service_name(self) -> str:
        return FEDERATED_USER_SERVICE_NAME

    def get_action_service_prefix(self) -> str:
        return FEDERATED_USER_ACTION_SERVICE_PREFIX

    def get_resource_service_prefix(self) -> str:
        return FEDERATED_USER_RESOURCE_SERVICE_PREFIX

    def get_resource_based_policy_irrelevant_principal_types(self) -> Optional[Set[AwsPrincipalType]]:
        return None

    @classmethod
    def get_service_resources_resolver_type(cls) -> Type[ServiceResourcesResolverBase]:
        return FederatedUserServiceResourcesResolver

    @classmethod
    def get_service_actions_resolver_type(cls) -> Type[ServiceActionsResolverBase]:
        return FederatedUserServiceActionsResolver

    @classmethod
    def load_service_actions(cls, logger: Logger) -> Set[ServiceActionBase]:
        return FederatedUserAction.load_federated_user_actions(logger)

    @classmethod
    def load_service_resources(
        cls,
        _logger: Logger,
        aws_account_resources: AwsAccountResources,
        _iam_entities,
    ) -> Optional[Set[ServiceResourceBase]]:
        ret: Set[ServiceResourceBase] = set()
        for stmt_principal in aws_account_resources.yield_stmt_principals_from_resource_based_policy(
            AwsPrincipalType.AWS_STS_FEDERATED_USER_SESSION
        ):
            ret.add(FederatedUserResource(federated_principal=stmt_principal))
        return ret
