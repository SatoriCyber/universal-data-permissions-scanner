import re
from dataclasses import dataclass
from logging import Logger
from typing import List, Set

from serde import serde

from authz_analyzer.datastores.aws.actions.service_actions_resolver_base import ServiceActionsResolverBase
from authz_analyzer.datastores.aws.iam.policy import PolicyDocument
from authz_analyzer.datastores.aws.services.s3.s3_resources import S3ResourceType
from authz_analyzer.datastores.aws.services.service_base import ServiceActionBase
from authz_analyzer.models import PermissionLevel

S3_ACTION_SERVICE_PREFIX = "s3:"


@serde
@dataclass
class S3Action(ServiceActionBase):
    name: str
    resource_type: S3ResourceType
    permission_level: PermissionLevel

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def get_action_name(self) -> str:
        return self.name

    def get_action_permission_level(self) -> PermissionLevel:
        return self.permission_level

    @classmethod
    def load_s3_actions(cls, _logger: Logger) -> List[ServiceActionBase]:
        return s3_actions


@dataclass
class S3ServiceActionsResolver(ServiceActionsResolverBase):
    stmt_relative_id_regex: str
    resolved_actions: Set[S3Action]

    def is_empty(self) -> bool:
        return len(self.resolved_actions) == 0

    def merge(self, other: 'ServiceActionsResolverBase'):
        if isinstance(other, S3ServiceActionsResolver):
            self.resolved_actions.union(other.resolved_actions)

    @staticmethod
    def resolve_actions(stmt_relative_id_objects_regex: str, service_actions: List[S3Action]) -> Set[S3Action]:
        regex = re.compile(stmt_relative_id_objects_regex)
        bucket_matches: List[S3Action] = [s for s in service_actions if regex.search(s.get_action_name()) is not None]
        return set(bucket_matches)

    @classmethod
    def load(
        cls, _logger: Logger, stmt_relative_id_regex: str, service_actions: List[S3Action]
    ) -> 'ServiceActionsResolverBase':
        stmt_relative_id_regex = PolicyDocument.fix_stmt_regex_to_valid_regex(stmt_relative_id_regex)

        resolved_actions = S3ServiceActionsResolver.resolve_actions(stmt_relative_id_regex, service_actions)
        return cls(
            resolved_actions=resolved_actions,
            stmt_relative_id_regex=stmt_relative_id_regex,
        )


s3_actions: List[ServiceActionBase] = [
    S3Action("GetBucketPolicy", S3ResourceType.BUCKET, PermissionLevel.READ),
    S3Action("GetObject", S3ResourceType.OBJECT, PermissionLevel.READ),
    S3Action("DeleteObject", S3ResourceType.OBJECT, PermissionLevel.WRITE),
]