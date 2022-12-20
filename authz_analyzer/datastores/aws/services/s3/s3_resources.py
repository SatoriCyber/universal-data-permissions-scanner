import re
from dataclasses import dataclass
from enum import Enum, auto
from logging import Logger
from typing import Any, Dict, Iterable, List, Optional, Set, Type, Union, cast

from authz_analyzer.datastores.aws.resources.service_resources_resolver_base import ServiceResourcesResolverBase
from authz_analyzer.datastores.aws.services.s3.bucket import S3Bucket


class S3ResourceType(Enum):
    # Resource types defined by Amazon S3: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html
    BUCKET = auto()
    OBJECT = auto()


@dataclass
class S3ServiceResourcesResolver(ServiceResourcesResolverBase):
    stmt_relative_id_buckets_regex: str
    stmt_relative_id_objects_regex: Optional[str]
    resolved_buckets: Set[S3Bucket]

    def is_empty(self) -> bool:
        return len(self.resolved_buckets) == 0

    def merge(self, other: ServiceResourcesResolverBase):
        if isinstance(other, S3ServiceResourcesResolver):
            self.resolved_buckets.union(other.resolved_buckets)

    @staticmethod
    def resolve_buckets_by_regex(
        stmt_relative_id_objects_regex: str, service_resources: List[S3Bucket]
    ) -> Set[S3Bucket]:
        regex = re.compile(stmt_relative_id_objects_regex)
        bucket_matches: List[S3Bucket] = [
            s for s in service_resources if regex.search(s.get_resource_name()) is not None
        ]
        return set(bucket_matches)

    @classmethod
    def load(
        cls, logger: Logger, stmt_relative_id_regex: str, service_resources: List[S3Bucket]
    ) -> 'S3ServiceResourcesResolver':
        res = stmt_relative_id_regex.split('/', 1)
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html
        # aws traits the '?' as regex '.' (any character)
        stmt_relative_id_buckets_regex: str = res[0].replace("?", ".")
        stmt_relative_id_objects_regex: Optional[str] = None
        if len(res) == 2:
            stmt_relative_id_objects_regex = res[1].replace("?", ".")

        resolved_buckets = S3ServiceResourcesResolver.resolve_buckets_by_regex(
            stmt_relative_id_buckets_regex, service_resources
        )
        return cls(
            resolved_buckets=resolved_buckets,
            stmt_relative_id_objects_regex=stmt_relative_id_objects_regex,
            stmt_relative_id_buckets_regex=stmt_relative_id_buckets_regex,
        )
