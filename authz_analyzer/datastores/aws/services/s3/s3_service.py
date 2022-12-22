from logging import Logger
from typing import List, Set

from boto3 import Session
from serde import serde

from authz_analyzer.datastores.aws.services.s3.bucket import S3_RESOURCE_SERVICE_PREFIX, S3Bucket, get_buckets
from authz_analyzer.datastores.aws.services.s3.s3_actions import (
    S3_ACTION_SERVICE_PREFIX,
    S3Action,
    S3ServiceActionsResolver,
)
from authz_analyzer.datastores.aws.services.s3.s3_resources import S3ServiceResourcesResolver
from authz_analyzer.datastores.aws.services.service_base import (
    ServiceActionBase,
    ServiceActionsResolverBase,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
    ServiceType,
)

S3_SERVICE_NAME = "s3"


@serde
class S3ServiceType(ServiceType):
    def get_resource_service_prefix(self) -> str:
        return S3_RESOURCE_SERVICE_PREFIX

    def get_action_service_prefix(self) -> str:
        return S3_ACTION_SERVICE_PREFIX

    def get_service_name(self) -> str:
        return S3_SERVICE_NAME
        
    @classmethod
    def load_resolver_service_resources(
        cls, logger: Logger, stmt_relative_id_regexes: List[str], service_resources: List[ServiceResourceBase], resolved_actions: Set[ServiceActionBase],
    ) -> ServiceResourcesResolverBase:
        s3_buckets: List[S3Bucket] = [s for s in service_resources if isinstance(s, S3Bucket)]
        resolved_s3_actions: Set[S3Action] = set([a for a in resolved_actions if isinstance(a, S3Action)])
        return S3ServiceResourcesResolver.load(logger, stmt_relative_id_regexes, s3_buckets, resolved_s3_actions)
    
    @classmethod
    def load_service_resources_from_session(cls, logger: Logger, session: Session) -> List[ServiceResourceBase]:
        # Get the buckets to analyzed
        buckets = get_buckets(session)
        logger.info(f"Got buckets to analyzed: {buckets}")
        return buckets

    @classmethod
    def load_resolver_service_actions(
        cls, logger: Logger, stmt_relative_id_regexes: List[str], service_actions: List[ServiceActionBase]
    ) -> ServiceActionsResolverBase:
        s3_actions: List[S3Action] = [s for s in service_actions if isinstance(s, S3Action)]
        return S3ServiceActionsResolver.load(logger, stmt_relative_id_regexes, s3_actions)

    @classmethod
    def load_service_actions(cls, logger: Logger) -> List[ServiceActionBase]:
        return S3Action.load_s3_actions(logger)