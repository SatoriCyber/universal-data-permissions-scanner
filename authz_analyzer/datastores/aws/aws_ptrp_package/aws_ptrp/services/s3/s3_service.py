from logging import Logger
from typing import List, Set, Type

from boto3 import Session
from serde import serde

from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.services.s3.bucket import S3_RESOURCE_SERVICE_PREFIX, get_buckets
from aws_ptrp.services.s3.s3_actions import (
    S3_ACTION_SERVICE_PREFIX,
    S3Action,
    S3ServiceActionsResolver,
)
from aws_ptrp.services.s3.s3_resources import S3ServiceResourcesResolver
from aws_ptrp.services import (
    ServiceActionBase,
    ServiceActionsResolverBase,
    ServiceResourceBase,
    ServiceResourceType,
    ServiceResourcesResolverBase,
)

S3_SERVICE_NAME = "s3_service"


@serde
class S3ServiceType(ServiceResourceType):
    def get_resource_service_prefix(self) -> str:
        return S3_RESOURCE_SERVICE_PREFIX

    def get_action_service_prefix(self) -> str:
        return S3_ACTION_SERVICE_PREFIX

    def get_service_name(self) -> str:
        return S3_SERVICE_NAME

    @classmethod
    def get_service_resources_resolver_type(cls) -> Type[ServiceResourcesResolverBase]:
        return S3ServiceResourcesResolver

    @classmethod
    def get_service_actions_resolver_type(cls) -> Type[ServiceActionsResolverBase]:
        return S3ServiceActionsResolver

    @classmethod
    def load_service_resources(
        cls, logger: Logger, session: Session, _iam_entities: IAMEntities
    ) -> Set[ServiceResourceBase]:
        # Get the buckets to analyzed
        buckets = get_buckets(session)
        logger.info(f"Got buckets to analyzed: {buckets}")
        return buckets

    @classmethod
    def load_service_actions(cls, logger: Logger) -> List[ServiceActionBase]:
        return S3Action.load_s3_actions(logger)
