from typing import Dict, Any, Optional, Type, List, Union, Set, Iterable, cast
from boto3 import Session
from dataclasses import dataclass
from logging import Logger
from authz_analyzer.datastores.aws.services.service_base import ServiceType, ServiceResourceBase, ServiceActionBase
from authz_analyzer.datastores.aws.resources.service_resources_resolver_base import ServiceResourcesResolverBase
from authz_analyzer.datastores.aws.actions.service_actions_resolver_base import ServiceActionsResolverBase
from authz_analyzer.datastores.aws.services.s3.bucket import S3Bucket, get_buckets, S3_RESOURCE_SERVICE_PREFIX
from authz_analyzer.datastores.aws.services.s3.s3_resources_resolver import S3ServiceResourcesResolver
from serde import serde


S3_SERVICE_NAME = "s3"


@serde
class S3ServiceType(ServiceType):
    def get_resource_service_prefix(self) -> str:
        return S3_RESOURCE_SERVICE_PREFIX

    def get_action_service_prefix(self) -> str:
        return "S3_ACTION_SERVICE_PREFIX"

    def get_service_name(self) -> str:
        return S3_SERVICE_NAME
        
    @classmethod
    def load_resolver_service_resources(
        cls, logger: Logger, stmt_relative_id_regex: str, service_resources: List[ServiceResourceBase]
    ) -> ServiceResourcesResolverBase:
        s3_buckets: List[S3Bucket] = [s for s in service_resources if isinstance(s, S3Bucket)]
        return S3ServiceResourcesResolver.load(logger, stmt_relative_id_regex, s3_buckets)
    
    @classmethod
    def load_service_resources_from_session(cls, logger: Logger, session: Session) -> List[ServiceResourceBase]:
        # Get the buckets to analyzed
        buckets = get_buckets(session)
        logger.info(f"Got buckets to analyzed: {buckets}")
        return buckets

    @classmethod
    def load_resolver_service_actions(
        cls, logger: Logger, stmt_relative_id_regex: str, service_actions: List[ServiceActionBase]
    ) -> ServiceActionsResolverBase:
        pass # TODO

    @classmethod
    def load_service_actions(cls, logger: Logger) -> List[ServiceActionBase]:
        pass # TODO