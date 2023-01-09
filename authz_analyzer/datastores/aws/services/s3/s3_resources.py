import re
from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set

from authz_analyzer.datastores.aws.iam.policy.policy_document_utils import fix_stmt_regex_to_valid_regex
from authz_analyzer.datastores.aws.iam.policy.principal import StmtPrincipal
from authz_analyzer.datastores.aws.services.s3.bucket import S3Bucket
from authz_analyzer.datastores.aws.services.s3.s3_actions import S3Action, S3ActionType, ResolvedS3BucketActions
from authz_analyzer.datastores.aws.services import (
    ServiceActionBase,
    ServiceResourceBase,
    ResolvedResourcesSingleStmt,
    ResolvedActionsSingleStmt,
    ServiceResourcesResolverBase,
)


@dataclass
class S3ResolvedStmt(ResolvedResourcesSingleStmt):
    resolved_principals: List[StmtPrincipal]
    resolved_buckets: Dict[S3Bucket, ResolvedS3BucketActions]
    # add here condition keys, tags, etc.. (single stmt scope)

    @property
    def resolved_stmt_principals(self) -> List[StmtPrincipal]:
        return self.resolved_principals

    @property
    def resolved_stmt_resources(self) -> Dict[ServiceResourceBase, ResolvedActionsSingleStmt]:
        return self.resolved_buckets  # type: ignore[return-value]


@dataclass
class S3ServiceResourcesResolver(ServiceResourcesResolverBase):
    resolved_stmts: List[S3ResolvedStmt]

    def get_resolved_stmts(self) -> List[ResolvedResourcesSingleStmt]:
        return self.resolved_stmts  # type: ignore[return-value]

    def subtract(self, other: ServiceResourcesResolverBase):
        pass

    @staticmethod
    def update_resolved_bucket_from_single_regex(
        resolved_buckets: Dict[S3Bucket, ResolvedS3BucketActions],
        stmt_relative_id_buckets_regex: str,
        stmt_relative_id_objects_regex: Optional[str],
        service_resources: List[S3Bucket],
        _resolved_stmt_principals: List[StmtPrincipal],
        resolved_stmt_actions_all: Set[S3Action],
        resolved_stmt_actions_bucket: Set[S3Action],
        resolved_stmt_actions_object: Set[S3Action],
    ):
        resolved_actions = resolved_stmt_actions_all
        buckets_regex_ends_with_wildcard: bool = stmt_relative_id_buckets_regex.endswith("*")
        if buckets_regex_ends_with_wildcard and stmt_relative_id_objects_regex is None:
            # "arn:aws:s3:::*bucket_name*" -> relevant actions type are buckets & objects
            resolved_actions = resolved_stmt_actions_all
        elif stmt_relative_id_objects_regex == "":
            # "arn:aws:s3:::*bucket_name*/" -> relevant actions type are None
            return
        elif stmt_relative_id_objects_regex:
            # stmt_relative_id_objects_regex is not None and not empty string
            # "arn:aws:s3:::*bucket_name*/abc*" -> relevant actions type are objects
            resolved_actions = resolved_stmt_actions_object
        else:
            # stmt_relative_id_objects_regex is None and buckets_regex_ends_with_wildcard is not
            # "arn:aws:s3:::*bucket_name" -> relevant actions type are buckets
            resolved_actions = resolved_stmt_actions_bucket

        if not resolved_actions:
            return

        regex = re.compile(fix_stmt_regex_to_valid_regex(stmt_relative_id_buckets_regex, with_case_sensitive=True))
        for bucket in service_resources:
            if regex.match(bucket.get_resource_name()) is not None:
                resolved_bucket_actions: Optional[ResolvedS3BucketActions] = resolved_buckets.get(bucket)
                if resolved_bucket_actions:
                    resolved_bucket_actions.add(resolved_actions, stmt_relative_id_objects_regex)
                else:
                    resolved_buckets[bucket] = ResolvedS3BucketActions.load(
                        resolved_actions, stmt_relative_id_objects_regex
                    )

    @classmethod
    def load_from_single_stmt(
        cls,
        _logger: Logger,
        stmt_relative_id_regexes: List[str],
        service_resources: Set[ServiceResourceBase],
        resolved_stmt_principals: List[StmtPrincipal],
        resolved_stmt_actions: Set[ServiceActionBase],
    ) -> 'S3ServiceResourcesResolver':
        resolved_buckets: Dict[S3Bucket, ResolvedS3BucketActions] = dict()

        s3_buckets: List[S3Bucket] = [s for s in service_resources if isinstance(s, S3Bucket)]
        resolved_stmt_s3_actions: Set[S3Action] = set([a for a in resolved_stmt_actions if isinstance(a, S3Action)])
        resolved_stmt_actions_bucket: Set[S3Action] = set(
            filter(lambda x: x.action_type == S3ActionType.BUCKET, resolved_stmt_s3_actions)
        )
        resolved_stmt_actions_object: Set[S3Action] = set(
            filter(lambda x: x.action_type == S3ActionType.OBJECT, resolved_stmt_s3_actions)
        )

        for stmt_relative_id_regex in stmt_relative_id_regexes:
            res = stmt_relative_id_regex.split('/', 1)
            stmt_relative_id_buckets_regex: str = res[0]
            stmt_relative_id_objects_regex: Optional[str] = None
            if len(res) == 2:
                stmt_relative_id_objects_regex = res[1]

            S3ServiceResourcesResolver.update_resolved_bucket_from_single_regex(
                resolved_buckets,
                stmt_relative_id_buckets_regex,
                stmt_relative_id_objects_regex,
                s3_buckets,
                resolved_stmt_principals,
                resolved_stmt_s3_actions,
                resolved_stmt_actions_bucket,
                resolved_stmt_actions_object,
            )

        resolved_stmt = S3ResolvedStmt(resolved_buckets=resolved_buckets, resolved_principals=resolved_stmt_principals)
        return cls(resolved_stmts=[resolved_stmt])
