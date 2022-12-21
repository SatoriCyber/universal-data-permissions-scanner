import re
from dataclasses import dataclass
from enum import Enum, auto
from logging import Logger
from typing import List, Optional, Set

from authz_analyzer.datastores.aws.iam.policy import PolicyDocument
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
            s for s in service_resources if regex.match(s.get_resource_name()) is not None
        ]
        return set(bucket_matches)

    @classmethod
    def load(
        cls, _logger: Logger, stmt_relative_id_regex: str, service_resources: List[S3Bucket]
    ) -> 'S3ServiceResourcesResolver':
        stmt_relative_id_regex = PolicyDocument.fix_stmt_regex_to_valid_regex(stmt_relative_id_regex)
        res = stmt_relative_id_regex.split('/', 1)
        stmt_relative_id_buckets_regex: str = res[0]
        stmt_relative_id_objects_regex: Optional[str] = None
        if len(res) == 2:
            stmt_relative_id_objects_regex = res[1]

        resolved_buckets = S3ServiceResourcesResolver.resolve_buckets_by_regex(
            stmt_relative_id_buckets_regex, service_resources
        )
        return cls(
            resolved_buckets=resolved_buckets,
            stmt_relative_id_objects_regex=stmt_relative_id_objects_regex,
            stmt_relative_id_buckets_regex=stmt_relative_id_buckets_regex,
        )
