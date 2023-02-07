from dataclasses import dataclass
from enum import Enum, auto
from logging import Logger
from typing import List, Optional, Set

from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpActionPermissionLevel
from aws_ptrp.services import ResolvedActionsSingleStmt, ServiceActionBase, ServiceActionsResolverBase
from aws_ptrp.utils.regex_subset import is_aws_regex_full_subset
from aws_ptrp.utils.serde import serde_enum_field
from serde import serde

S3_ACTION_SERVICE_PREFIX = "s3:"


class S3ActionType(Enum):
    # Resource types defined by Amazon S3: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html
    BUCKET = auto()
    OBJECT = auto()


@serde
@dataclass
class S3Action(ServiceActionBase):
    name: str
    action_type: S3ActionType = serde_enum_field(S3ActionType)
    permission_level: AwsPtrpActionPermissionLevel = serde_enum_field(AwsPtrpActionPermissionLevel)

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def get_action_name(self) -> str:
        return self.name

    def get_action_permission_level(self) -> AwsPtrpActionPermissionLevel:
        return self.permission_level

    @classmethod
    def load_s3_actions(cls, _logger: Logger) -> List[ServiceActionBase]:
        return s3_actions


@dataclass
class ResolvedS3BucketActions(ResolvedActionsSingleStmt):
    stmt_relative_id_objects_regexes: List[str]
    actions: Set[S3Action]

    @property
    def resolved_stmt_actions(self) -> Set[ServiceActionBase]:
        return self.actions  # type: ignore[return-value]

    def add(self, actions: Set[S3Action], stmt_relative_id_objects_regex: Optional[str]):
        if stmt_relative_id_objects_regex is not None:
            self.stmt_relative_id_objects_regexes.append(stmt_relative_id_objects_regex)
        self.actions = self.actions.union(actions)

    @classmethod
    def load(cls, actions: Set[S3Action], stmt_relative_id_objects_regex: Optional[str]) -> 'ResolvedS3BucketActions':
        stmt_relative_id_objects_regexes = []
        if stmt_relative_id_objects_regex is not None:
            stmt_relative_id_objects_regexes.append(stmt_relative_id_objects_regex)
        return cls(actions=actions, stmt_relative_id_objects_regexes=stmt_relative_id_objects_regexes)

    def difference(self, other: 'ResolvedActionsSingleStmt'):
        """
        the function checks that each object regex in self is a 'full subset' of all regexes in other, and if so, it removes the object actions (in addition to the bucket actions)
        """
        difference_also_on_object_actions = True
        if isinstance(other, ResolvedS3BucketActions):
            for o_regex in other.stmt_relative_id_objects_regexes:
                for s_regex in self.stmt_relative_id_objects_regexes:
                    difference_also_on_object_actions = difference_also_on_object_actions and is_aws_regex_full_subset(
                        o_regex, s_regex
                    )
                    if difference_also_on_object_actions is False:
                        break
                if difference_also_on_object_actions is False:
                    break

            if difference_also_on_object_actions is True:
                actions_to_difference = other.actions
            else:
                # We remove only the bucket actions
                actions_to_difference = set(filter(lambda a: a.action_type == S3ActionType.BUCKET, other.actions))

            self.resolved_stmt_actions.difference_update(actions_to_difference)


@dataclass
class S3ServiceActionsResolver(ServiceActionsResolverBase):
    resolved_actions: Set[S3Action]

    def get_resolved_actions(self) -> Set[ServiceActionBase]:
        return self.resolved_actions  # type: ignore[return-value]

    @classmethod
    def load_from_single_stmt(
        cls, _logger: Logger, stmt_regexes: List[str], service_actions: List[ServiceActionBase]
    ) -> 'ServiceActionsResolverBase':
        resolved_actions = ServiceActionsResolverBase.resolve_actions_from_single_stmt_regexes(
            stmt_regexes, service_actions
        )
        s3_resolved_actions: Set[S3Action] = set([s for s in resolved_actions if isinstance(s, S3Action)])
        return cls(resolved_actions=s3_resolved_actions)


s3_actions: List[ServiceActionBase] = [
    # S3Action("AbortMultipartUpload", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.WRITE),
    S3Action("BypassGovernanceRetention", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("CreateBucket", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("DeleteBucket", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("DeleteBucketPolicy", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("DeleteBucketWebsite", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("DeleteObject", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.WRITE),
    S3Action("DeleteObjectTagging", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.WRITE),
    S3Action("DeleteObjectVersion", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.WRITE),
    S3Action("DeleteObjectVersionTagging", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.WRITE),
    # S3Action("GetAccelerateConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetAnalyticsConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketAcl", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketCORS", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketCORS", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketLocation", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketLogging", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketNotification", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketObjectLockConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketOwnershipControls", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketPolicy", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketPolicyStatus", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketPublicAccessBlock", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketRequestPayment", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketTagging", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketVersioning", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetBucketWebsite", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetEncryptionConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetIntelligentTieringConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetInventoryConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetLifecycleConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetMetricsConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    S3Action("GetObject", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetObjectAcl", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    S3Action("GetObjectAttributes", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetObjectLegalHold", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetObjectRetention", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    S3Action("GetObjectTagging", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetObjectTorrent", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    S3Action("GetObjectVersion", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetObjectVersionAcl", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    S3Action("GetObjectVersionAttributes", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetObjectVersionForReplication", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    S3Action("GetObjectVersionTagging", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetObjectVersionTorrent", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    # S3Action("GetReplicationConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("InitiateReplication", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.WRITE),
    S3Action("ListBucket", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("ListBucketMultipartUploads", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    S3Action("ListBucketVersions", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.READ),
    # S3Action("ListMultipartUploadParts", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.READ),
    S3Action("ObjectOwnerOverrideToBucketOwner", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutAccelerateConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutAnalyticsConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketAcl", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketCORS", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketLogging", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketNotification", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketObjectLockConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketOwnershipControls", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketPolicy", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketPublicAccessBlock", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketRequestPayment", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketTagging", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketVersioning", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutBucketWebsite", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutEncryptionConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutIntelligentTieringConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutInventoryConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutLifecycleConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutMetricsConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutObject", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.WRITE),
    S3Action("PutObjectAcl", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutObjectLegalHold", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutObjectRetention", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutObjectTagging", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutObjectVersionAcl", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutObjectVersionTagging", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("PutReplicationConfiguration", S3ActionType.BUCKET, AwsPtrpActionPermissionLevel.FULL),
    S3Action("ReplicateDelete", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("ReplicateObject", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("ReplicateTags", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.FULL),
    S3Action("RestoreObject", S3ActionType.OBJECT, AwsPtrpActionPermissionLevel.WRITE),
]
