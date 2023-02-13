from logging import Logger
from typing import Dict, Optional, Set, Type

from aws_ptrp.iam.policy.policy_document import Effect, PolicyDocument
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
    FederatedUserPrincipal,
    FederatedUserServiceResourcesResolver,
)
from aws_ptrp.services.s3.s3_resources import S3Bucket
from aws_ptrp.services.s3.s3_service import S3Service
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
        resources_loaded_from_session: Dict['ServiceResourceType', Set[ServiceResourceBase]],
        _iam_entities,
    ) -> Optional[Set[ServiceResourceBase]]:
        # s3 bucket is resource which might have resource-based policy -> extract all federated user from the policy
        s3_buckets: Optional[Set[ServiceResourceBase]] = resources_loaded_from_session.get(S3Service())
        if not s3_buckets:
            return None

        ret: Set[ServiceResourceBase] = set()
        for s3_bucket in s3_buckets:
            if not isinstance(s3_bucket, S3Bucket):
                continue
            bucket_policy: Optional[PolicyDocument] = s3_bucket.get_resource_policy()
            if bucket_policy is None:
                continue
            for principal in bucket_policy.yield_stmt_principals(Effect.Allow):
                if principal.is_federated_user_principal():
                    ret.add(FederatedUserPrincipal(federated_principal=principal))

        return ret
