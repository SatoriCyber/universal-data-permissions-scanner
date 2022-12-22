import re
from dataclasses import dataclass
from enum import Enum, auto
from logging import Logger
from typing import List, Set

from serde import serde

from authz_analyzer.datastores.aws.iam.policy import PolicyDocument
from authz_analyzer.datastores.aws.services.service_base import ServiceActionBase, ServiceActionsResolverBase
from authz_analyzer.models import PermissionLevel

S3_ACTION_SERVICE_PREFIX = "s3:"


class S3ActionType(Enum):
    # Resource types defined by Amazon S3: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html
    BUCKET = auto()
    OBJECT = auto()


@serde
@dataclass
class S3Action(ServiceActionBase):
    name: str
    action_type: S3ActionType
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
    resolved_actions: Set[S3Action]

    def is_empty(self) -> bool:
        return len(self.resolved_actions) == 0

    def get_resolved_actions(self) -> Set[ServiceActionBase]:
        return self.resolved_actions  # type: ignore[return-value]

    @staticmethod
    def resolve_actions(stmt_relative_id_objects_regex: str, service_actions: List[S3Action]) -> Set[S3Action]:
        # actions are case insensitive
        regex = re.compile(f"(?i){stmt_relative_id_objects_regex}")
        service_actions_matches: List[S3Action] = [s for s in service_actions if regex.match(s.get_action_name()) is not None]
        return set(service_actions_matches)

    @classmethod
    def load(
        cls, _logger: Logger, stmt_relative_id_regexes: List[str], service_actions: List[S3Action]
    ) -> 'ServiceActionsResolverBase':
        resolved_actions: Set[S3Action] = set()
        for stmt_relative_id_regex in stmt_relative_id_regexes:
            stmt_relative_id_regex = PolicyDocument.fix_stmt_regex_to_valid_regex(stmt_relative_id_regex)
            resolved_actions = resolved_actions.union(S3ServiceActionsResolver.resolve_actions(stmt_relative_id_regex, service_actions))
            
        return cls(
            resolved_actions=resolved_actions,
        )


s3_actions: List[ServiceActionBase] = [
    S3Action("GetBucketPolicy", S3ActionType.BUCKET, PermissionLevel.READ),
    S3Action("GetObject", S3ActionType.OBJECT, PermissionLevel.READ),
    S3Action("DeleteObject", S3ActionType.OBJECT, PermissionLevel.WRITE),
]