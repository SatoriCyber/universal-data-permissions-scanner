import re
from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Generator, Tuple

from authz_analyzer.datastores.aws.iam.policy.policy_document_utils import fix_stmt_regex_to_valid_regex
from authz_analyzer.datastores.aws.services.s3.bucket import S3Bucket
from authz_analyzer.datastores.aws.services.s3.s3_actions import S3Action, S3ActionType
from authz_analyzer.datastores.aws.services import (
    ServiceActionBase,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
)


@dataclass
class ResolvedBucketActions:
    stmt_relative_id_objects_regexes: List[str]
    actions: Set[S3Action]

    def add(self, actions: Set[S3Action], stmt_relative_id_objects_regex: Optional[str]):
        if stmt_relative_id_objects_regex is not None:
            self.stmt_relative_id_objects_regexes.append(stmt_relative_id_objects_regex)
        self.actions = self.actions.union(actions)

    @classmethod
    def load(cls, actions: Set[S3Action], stmt_relative_id_objects_regex: Optional[str]) -> 'ResolvedBucketActions':
        stmt_relative_id_objects_regexes = []
        if stmt_relative_id_objects_regex is not None:
            stmt_relative_id_objects_regexes.append(stmt_relative_id_objects_regex)
        return cls(actions=actions, stmt_relative_id_objects_regexes=stmt_relative_id_objects_regexes)


@dataclass
class S3ServiceResourcesResolver(ServiceResourcesResolverBase):
    resolved_buckets: List[Dict[S3Bucket, ResolvedBucketActions]]

    def is_empty(self) -> bool:
        return len(self.resolved_buckets) == 0

    def add_from_single_stmt(self, other: ServiceResourcesResolverBase):
        if isinstance(other, S3ServiceResourcesResolver):
            self.resolved_buckets.extend(other.resolved_buckets)

    def yield_resolved_resource_with_actions(
        self,
    ) -> Generator[Tuple[ServiceResourceBase, Set[ServiceActionBase]], None, None]:
        for resolved_buckets_dict in self.resolved_buckets:
            for bucket, resolved_bucket_actions in resolved_buckets_dict.items():
                yield (bucket, resolved_bucket_actions.actions)  # type: ignore

    @staticmethod
    def update_resolved_bucket_from_single_regex(
        resolved_buckets: Dict[S3Bucket, ResolvedBucketActions],
        stmt_relative_id_buckets_regex: str,
        stmt_relative_id_objects_regex: Optional[str],
        service_resources: List[S3Bucket],
        resolved_actions_all: Set[S3Action],
        resolved_actions_bucket: Set[S3Action],
        resolved_actions_object: Set[S3Action],
    ):
        resolved_actions = resolved_actions_all
        buckets_regex_ends_with_wildcard: bool = stmt_relative_id_buckets_regex.endswith("*")
        if buckets_regex_ends_with_wildcard and stmt_relative_id_objects_regex is None:
            # "arn:aws:s3:::*bucket_name*" -> relevant actions type are buckets & objects
            resolved_actions = resolved_actions_all
        elif stmt_relative_id_objects_regex == "":
            # "arn:aws:s3:::*bucket_name*/" -> relevant actions type are None
            return
        elif stmt_relative_id_objects_regex:
            # stmt_relative_id_objects_regex is not None and not empty string
            # "arn:aws:s3:::*bucket_name*/abc*" -> relevant actions type are objects
            resolved_actions = resolved_actions_object
        else:
            # stmt_relative_id_objects_regex is None and buckets_regex_ends_with_wildcard is not
            # "arn:aws:s3:::*bucket_name" -> relevant actions type are buckets
            resolved_actions = resolved_actions_bucket

        if not resolved_actions:
            return

        regex = re.compile(fix_stmt_regex_to_valid_regex(stmt_relative_id_buckets_regex, with_case_insensitive=False))
        for bucket in service_resources:
            if regex.match(bucket.get_resource_name()) is not None:
                resolved_bucket_actions: Optional[ResolvedBucketActions] = resolved_buckets.get(bucket)
                if resolved_bucket_actions:
                    resolved_bucket_actions.add(resolved_actions, stmt_relative_id_objects_regex)
                else:
                    resolved_buckets[bucket] = ResolvedBucketActions.load(
                        resolved_actions, stmt_relative_id_objects_regex
                    )

    @classmethod
    def load(
        cls,
        _logger: Logger,
        stmt_relative_id_regexes: List[str],
        service_resources: List[S3Bucket],
        resolved_actions: Set[S3Action],
    ) -> 'S3ServiceResourcesResolver':
        resolved_buckets: Dict[S3Bucket, ResolvedBucketActions] = dict()
        resolved_actions_bucket: Set[S3Action] = set(
            filter(lambda x: x.action_type == S3ActionType.BUCKET, resolved_actions)
        )
        resolved_actions_object: Set[S3Action] = set(
            filter(lambda x: x.action_type == S3ActionType.OBJECT, resolved_actions)
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
                service_resources,
                resolved_actions,
                resolved_actions_bucket,
                resolved_actions_object,
            )

        return cls(resolved_buckets=[resolved_buckets])
