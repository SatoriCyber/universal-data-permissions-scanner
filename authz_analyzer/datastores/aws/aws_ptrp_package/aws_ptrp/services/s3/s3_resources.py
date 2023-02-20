import re
from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Tuple

from aws_ptrp.iam.policy.policy_document_utils import fix_stmt_regex_to_valid_regex
from aws_ptrp.services import (
    ResolvedSingleStmt,
    ResolvedSingleStmtGetter,
    ServiceResourcesResolverBase,
    StmtResourcesToResolveCtx,
)
from aws_ptrp.services.s3.bucket import S3Bucket
from aws_ptrp.services.s3.s3_actions import ResolvedS3BucketActions, S3Action, S3ActionType


@dataclass
class S3ResolvedStmt(ResolvedSingleStmtGetter):
    resolved_stmt: ResolvedSingleStmt

    def get(self) -> ResolvedSingleStmt:
        return self.resolved_stmt


@dataclass
class S3ServiceResourcesResolver(ServiceResourcesResolverBase):
    resolved_stmts: List[S3ResolvedStmt]

    def get_resolved_stmts(self) -> List[ResolvedSingleStmtGetter]:
        return self.resolved_stmts  # type: ignore[return-value]

    @staticmethod
    def get_resolved_actions_and_fixed_relative_object_regex(
        stmt_relative_id_buckets_regex: str,
        stmt_relative_id_objects_regex: Optional[str],
        resolved_stmt_actions_all: Set[S3Action],
        resolved_stmt_actions_bucket: Set[S3Action],
        resolved_stmt_actions_object: Set[S3Action],
    ) -> Tuple[Set[S3Action], Optional[str]]:
        resolved_actions = resolved_stmt_actions_all
        buckets_regex_ends_with_wildcard: bool = stmt_relative_id_buckets_regex.endswith("*")
        fixed_stmt_relative_id_objects_regex = stmt_relative_id_objects_regex
        if buckets_regex_ends_with_wildcard and stmt_relative_id_objects_regex is None:
            # "arn:aws:s3:::*bucket_name*" -> relevant actions type are buckets & objects
            resolved_actions = resolved_stmt_actions_all
            fixed_stmt_relative_id_objects_regex = "*"  #  the objects regex is actually wildcard
        elif stmt_relative_id_objects_regex == "":
            # "arn:aws:s3:::*bucket_name*/" -> relevant actions type are None
            resolved_actions = set()
        elif stmt_relative_id_objects_regex:
            # stmt_relative_id_objects_regex is not None and not empty string
            # "arn:aws:s3:::*bucket_name*/abc*" -> relevant actions type are objects
            resolved_actions = resolved_stmt_actions_object
        else:
            # stmt_relative_id_objects_regex is None and buckets_regex_ends_with_wildcard is not
            # "arn:aws:s3:::*bucket_name" -> relevant actions type are buckets
            resolved_actions = resolved_stmt_actions_bucket

        return resolved_actions, fixed_stmt_relative_id_objects_regex

    @staticmethod
    def get_matched_buckets_from_single_regex(
        stmt_relative_id_buckets_regex: str,
        service_resources: List[S3Bucket],
    ) -> Set[S3Bucket]:
        regex = re.compile(fix_stmt_regex_to_valid_regex(stmt_relative_id_buckets_regex, with_case_sensitive=True))
        return set(filter(lambda bucket: regex.match(bucket.get_resource_name()) is not None, service_resources))

    @staticmethod
    def add_resolved_actions_to_matched_buckets(
        resolved_buckets: Dict[S3Bucket, ResolvedS3BucketActions],
        resolved_actions: Set[S3Action],
        stmt_relative_id_objects_regex: Optional[str],
        matched_buckets: Set[S3Bucket],
    ):
        for bucket in matched_buckets:
            resolved_bucket_actions: Optional[ResolvedS3BucketActions] = resolved_buckets.get(bucket)
            if resolved_bucket_actions:
                resolved_bucket_actions.add(resolved_actions, stmt_relative_id_objects_regex)
            else:
                resolved_buckets[bucket] = ResolvedS3BucketActions.load(
                    resolved_actions.copy(), stmt_relative_id_objects_regex, False
                )

    @staticmethod
    def resolved_difference_for_not_resource_annotated_buckets(
        resolved_buckets: Dict[S3Bucket, ResolvedS3BucketActions],
        resolved_actions: Set[S3Action],
        s3_buckets: List[S3Bucket],
    ):
        for bucket in s3_buckets:
            to_differ = resolved_buckets.get(bucket)
            if to_differ:
                resolved_action_for_bucket = ResolvedS3BucketActions.load_from_not_resource_difference(
                    to_differ, resolved_actions
                )
                # After difference, no actions are left for the bucket
                if resolved_action_for_bucket is None:
                    resolved_buckets.pop(bucket)
                else:
                    resolved_buckets[bucket] = resolved_action_for_bucket
            else:
                resolved_buckets[bucket] = ResolvedS3BucketActions.load(resolved_actions.copy(), "*", False)

    @classmethod
    def load_from_single_stmt(
        cls, _logger: Logger, stmt_ctx: StmtResourcesToResolveCtx, not_resource_annotated: bool
    ) -> 'S3ServiceResourcesResolver':
        resolved_buckets: Dict[S3Bucket, ResolvedS3BucketActions] = {}
        s3_buckets: List[S3Bucket] = [s for s in stmt_ctx.service_resources if isinstance(s, S3Bucket)]
        resolved_stmt_s3_actions: Set[S3Action] = set(
            [a for a in stmt_ctx.resolved_stmt_actions if isinstance(a, S3Action)]
        )
        resolved_stmt_actions_bucket: Set[S3Action] = set(
            filter(lambda x: x.action_type == S3ActionType.BUCKET, resolved_stmt_s3_actions)
        )
        resolved_stmt_actions_object: Set[S3Action] = set(
            filter(lambda x: x.action_type == S3ActionType.OBJECT, resolved_stmt_s3_actions)
        )

        for stmt_relative_id_regex in stmt_ctx.stmt_relative_id_resource_regexes:
            res = stmt_relative_id_regex.split('/', 1)
            stmt_relative_id_buckets_regex: str = res[0]
            stmt_relative_id_objects_regex: Optional[str] = None
            if len(res) == 2:
                stmt_relative_id_objects_regex = res[1]

            (
                resolved_actions,
                fixed_stmt_relative_id_objects_regex,
            ) = S3ServiceResourcesResolver.get_resolved_actions_and_fixed_relative_object_regex(
                stmt_relative_id_buckets_regex,
                stmt_relative_id_objects_regex,
                resolved_stmt_s3_actions,
                resolved_stmt_actions_bucket,
                resolved_stmt_actions_object,
            )
            stmt_relative_id_objects_regex = fixed_stmt_relative_id_objects_regex

            if not resolved_actions:
                continue

            matched_buckets = S3ServiceResourcesResolver.get_matched_buckets_from_single_regex(
                stmt_relative_id_buckets_regex,
                s3_buckets,
            )

            S3ServiceResourcesResolver.add_resolved_actions_to_matched_buckets(
                resolved_buckets, resolved_actions, stmt_relative_id_objects_regex, matched_buckets
            )

        if not_resource_annotated:
            # Resolving actions for each buckets, and evaluate the difference between the previously resolved actions
            # resolved_buckets[bucket] currently holds the actions that matches the resources inside the NotResource section.
            S3ServiceResourcesResolver.resolved_difference_for_not_resource_annotated_buckets(
                resolved_buckets, resolved_stmt_s3_actions, s3_buckets
            )

        resolved_stmt: ResolvedSingleStmt = ResolvedSingleStmt.load(stmt_ctx, resolved_buckets)  # type: ignore
        s3_resolved_stmt = S3ResolvedStmt(
            resolved_stmt=resolved_stmt,
        )
        return cls(resolved_stmts=[s3_resolved_stmt])
