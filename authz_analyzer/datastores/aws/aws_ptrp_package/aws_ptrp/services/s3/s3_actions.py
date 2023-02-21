from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from logging import Logger
from typing import List, Optional, Set

from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpActionPermissionLevel
from aws_ptrp.services import (
    MethodOnStmtActionsResultType,
    ResolvedActionsSingleStmt,
    ServiceActionBase,
    ServiceActionsResolverBase,
)
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
    def load_s3_actions(cls, _logger: Logger) -> Set[ServiceActionBase]:
        return s3_actions


@dataclass
class ResolvedS3BucketActions(ResolvedActionsSingleStmt):
    stmt_relative_id_objects_regexes: List[str]
    actions: Set[S3Action]
    _not_resource_annotated: bool

    @property
    def resolved_stmt_actions(self) -> Set[ServiceActionBase]:
        return self.actions  # type: ignore[return-value]

    def add(self, actions: Set[S3Action], stmt_relative_id_objects_regex: Optional[str]):
        if stmt_relative_id_objects_regex is not None:
            self.stmt_relative_id_objects_regexes.append(stmt_relative_id_objects_regex)
        self.actions = self.actions.union(actions)

    @classmethod
    def load(
        cls, actions: Set[S3Action], stmt_relative_id_objects_regex: Optional[str], not_resource_annotated: bool
    ) -> ResolvedS3BucketActions:
        stmt_relative_id_objects_regexes = []
        if stmt_relative_id_objects_regex is not None:
            stmt_relative_id_objects_regexes.append(stmt_relative_id_objects_regex)
        return cls(
            actions=actions,
            stmt_relative_id_objects_regexes=stmt_relative_id_objects_regexes,
            _not_resource_annotated=not_resource_annotated,
        )

    @classmethod
    def load_with_object_regex_list(
        cls, actions: Set[S3Action], stmt_relative_id_objects_regex: List[str], not_resource_annotated: bool
    ) -> ResolvedS3BucketActions:
        stmt_relative_id_objects_regexes = []
        if stmt_relative_id_objects_regex:
            stmt_relative_id_objects_regexes.extend(stmt_relative_id_objects_regex)
        return cls(
            actions=actions,
            stmt_relative_id_objects_regexes=stmt_relative_id_objects_regexes,
            _not_resource_annotated=not_resource_annotated,
        )

    def are_all_object_regexes_full_subset_of_any_regex_in_other(self, other: ResolvedS3BucketActions) -> bool:
        for s_regex in self.stmt_relative_id_objects_regexes:
            if (
                any(is_aws_regex_full_subset(o_regex, s_regex) for o_regex in other.stmt_relative_id_objects_regexes)
                is False
            ):
                return False
        return True

    def difference(self, other: ResolvedActionsSingleStmt) -> MethodOnStmtActionsResultType:
        """
        This functions differs the s3 actions between 'self' and 'other'
        Bucket actions will always be removed. In case of object actions, it is depends on the relative object regexes in each one
        Generally, if each object regex in self is a 'full subset' of at least one regex in other, we removes the object actions (in addition to the bucket actions)
        If some(or both) of the statements are annotated with NotResource, in some cases we can solve the problem with the complements of each group
        """
        difference_also_on_object_actions = False
        ret = MethodOnStmtActionsResultType.APPLIED
        if isinstance(other, ResolvedS3BucketActions):
            self_not_resource_annotated = self.is_not_resource_annotated()
            other_not_resource_annotated = other.is_not_resource_annotated()
            object_actions_intersected = any(
                action
                for action in self.actions.intersection(other.actions)
                if action.action_type == S3ActionType.OBJECT
            )
            if self_not_resource_annotated is False and other_not_resource_annotated is False:
                if other.stmt_relative_id_objects_regexes:
                    difference_also_on_object_actions = self.are_all_object_regexes_full_subset_of_any_regex_in_other(
                        other
                    )

            elif self_not_resource_annotated is True and other_not_resource_annotated is True:
                # S < O <-> O' < S' (S' = complement(S), O' = complement(O)
                # If both statements are annotated with NotResource, we can solve the problem with the complements of each group
                if self.stmt_relative_id_objects_regexes:
                    difference_also_on_object_actions = other.are_all_object_regexes_full_subset_of_any_regex_in_other(
                        self
                    )

            elif self_not_resource_annotated is True and other_not_resource_annotated is False:
                # We cant really solve the problem with complements, so we will assume that we can remove the object actions
                # Only if other.stmt_relative_id_objects_regexes as a wildcard
                difference_also_on_object_actions = any(
                    o_regex == "*" for o_regex in other.stmt_relative_id_objects_regexes
                )
                # We will report about ignoring the difference if the object actions have a common in both statements
                if not difference_also_on_object_actions and object_actions_intersected:
                    ret = MethodOnStmtActionsResultType.IGNORE_METHOD_DIFFERENCE_WITH_S3_NOT_RESOURCE_OBJECT_REGEX

            elif self_not_resource_annotated is False and other_not_resource_annotated is True:
                # If only other is annotated with NotResource, we don't want to remove the object actions, since we
                # don't know if the object regexes are full subsets of each other
                difference_also_on_object_actions = False
                # We will report about ignoring the difference if the object actions have a common in both statements
                if object_actions_intersected:
                    ret = MethodOnStmtActionsResultType.IGNORE_METHOD_DIFFERENCE_WITH_S3_NOT_RESOURCE_OBJECT_REGEX

            if difference_also_on_object_actions is True:
                actions_to_difference = other.actions
            else:
                # We remove only the bucket actions
                actions_to_difference = set(filter(lambda a: a.action_type == S3ActionType.BUCKET, other.actions))

            self.resolved_stmt_actions.difference_update(actions_to_difference)

        return ret

    def is_not_resource_annotated(self) -> bool:
        return self._not_resource_annotated

    @classmethod
    def load_from_not_resource_difference(
        cls, other: ResolvedS3BucketActions, all_actions: Set[S3Action]
    ) -> Optional[ResolvedS3BucketActions]:
        # We make the difference while evaluating the resources in the policy with NotResource annotated,
        # so if the bucket relative object regex list has a '*', we want to remove the object actions as well
        difference_also_on_object_actions = any(
            object_regex == "*" for object_regex in other.stmt_relative_id_objects_regexes
        )

        if difference_also_on_object_actions is True:
            actions_to_difference = other.actions
            stmt_relative_id_objects_regexes = []
            not_resource_annotated = False
        else:
            # We remove only the bucket actions
            actions_to_difference = set(filter(lambda a: a.action_type == S3ActionType.BUCKET, other.actions))
            stmt_relative_id_objects_regexes = other.stmt_relative_id_objects_regexes
            not_resource_annotated = True

        resolved_actions = all_actions.difference(actions_to_difference)
        if not resolved_actions:
            ret = None
        else:
            ret = cls.load_with_object_regex_list(
                resolved_actions, stmt_relative_id_objects_regexes, not_resource_annotated
            )
        return ret


@dataclass
class S3ServiceActionsResolver(ServiceActionsResolverBase):
    resolved_actions: Set[S3Action]

    def get_resolved_actions(self) -> Set[ServiceActionBase]:
        return self.resolved_actions  # type: ignore[return-value]

    @classmethod
    def load_from_single_stmt(
        cls,
        _logger: Logger,
        stmt_regexes: List[str],
        service_actions: Set[ServiceActionBase],
        not_action_annotated: bool,
    ) -> 'ServiceActionsResolverBase':
        resolved_actions = ServiceActionsResolverBase.resolve_actions_from_single_stmt_regexes(
            stmt_regexes, service_actions, not_action_annotated
        )
        s3_resolved_actions: Set[S3Action] = set([s for s in resolved_actions if isinstance(s, S3Action)])
        return cls(resolved_actions=s3_resolved_actions)


s3_actions: Set[ServiceActionBase] = {
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
}
