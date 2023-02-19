from logging import Logger
from typing import Optional, Set, Type

from aws_ptrp.ptrp_models import AwsPrincipalType
from aws_ptrp.services import (
    ServiceActionBase,
    ServiceActionsResolverBase,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
    ServiceResourceType,
)
from aws_ptrp.services.s3.bucket import S3_RESOURCE_SERVICE_PREFIX, get_buckets
from aws_ptrp.services.s3.s3_actions import S3_ACTION_SERVICE_PREFIX, S3Action, S3ServiceActionsResolver
from aws_ptrp.services.s3.s3_resources import S3ServiceResourcesResolver
from boto3 import Session
from serde import serde

S3_SERVICE_NAME = "s3"


@serde
class S3Service(ServiceResourceType):
    def get_resource_service_prefix(self) -> str:
        return S3_RESOURCE_SERVICE_PREFIX

    def get_action_service_prefix(self) -> str:
        return S3_ACTION_SERVICE_PREFIX

    def get_service_name(self) -> str:
        return S3_SERVICE_NAME

    def get_resource_based_policy_irrelevant_principal_types(self) -> Optional[Set[AwsPrincipalType]]:
        return {AwsPrincipalType.SAML_SESSION, AwsPrincipalType.WEB_IDENTITY_SESSION}

    @classmethod
    def get_service_resources_resolver_type(cls) -> Type[ServiceResourcesResolverBase]:
        return S3ServiceResourcesResolver

    @classmethod
    def get_service_actions_resolver_type(cls) -> Type[ServiceActionsResolverBase]:
        return S3ServiceActionsResolver

    @classmethod
    def load_service_resources_from_session(
        cls, logger: Logger, session: Session, aws_account_id: str
    ) -> Optional[Set[ServiceResourceBase]]:
        # Get the buckets to analyzed
        buckets = get_buckets(session, aws_account_id)
        logger.info(f"Got buckets to analyzed: {buckets}")
        return buckets

    @classmethod
    def load_service_actions(cls, logger: Logger) -> Set[ServiceActionBase]:
        return S3Action.load_s3_actions(logger)
