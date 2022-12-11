"""Analyze authorization for S3.

"""

import json
from boto3 import Session
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from authz_analyzer.utils.aws.create_session import create_session_with_assume_role
from authz_analyzer.utils.aws.s3.bucket import get_buckets, S3Bucket
from authz_analyzer.utils.aws.iam.iam_users import get_iam_users, IAMUser
from authz_analyzer.utils.aws.iam.iam_groups import get_iam_groups, IAMGroup
from authz_analyzer.datastores.base import BaseAuthzAnalyzer
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE


@dataclass
class S3AuthzAnalyzerCtx:
    buckets_to_analyzed: Dict[str, S3Bucket]
    iam_users: Dict[str, IAMUser]
    iam_groups: Dict[str, IAMGroup]

    @classmethod
    def load(cls, logger, session: Session, session_master: Optional[Session]):
        # Get the buckets to analyzed
        buckets_to_analyzed = get_buckets(session)
        logger.info(f"Got buckets to analyzed: {buckets_to_analyzed.keys()}")

        # Get the iam users
        iam_users = get_iam_users(session)
        logger.info(f"Got iam_users: {iam_users.keys()}")

        # Get the iam groups
        iam_groups = get_iam_groups(session)
        logger.info(f"Got iam_groups: {iam_groups.keys()}")
        return cls(buckets_to_analyzed=buckets_to_analyzed, iam_users=iam_users, iam_groups=iam_groups)

    # for attached_policy in attached_policies:
    #     policy = Policy(**iam_client.get_policy(PolicyArn=attached_policy['PolicyArn'])["Policy"])
    #     response = iam_client.get_policy_version(
    #         PolicyArn=attached_policy['PolicyArn'],
    #         VersionId=policy.default_version_id
    #     )
    #     policy_document = PolicyDocument(**response['PolicyVersion']["Document"])
    

@dataclass
class S3AuthzAnalyzer(BaseAuthzAnalyzer):
    writer: BaseWriter
    logger: Logger
    master_account_id: Optional[str]
    master_account_role_name: Optional[str]
    account_id: str
    account_role_name: str

    @classmethod
    def connect(
        cls,
        master_account_id,
        master_account_role_name,
        account_id,
        account_role_name,
        logger: Optional[Logger] = None,
        output_format: OutputFormat = OutputFormat.Csv,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
    ):
        if logger is None:
            logger = get_logger(False)

        writer = get_writer(filename=output_path, format=output_format)

        return cls(
            logger=logger,
            writer=writer,
            master_account_id=master_account_id,
            master_account_role_name=master_account_role_name,
            account_id=account_id,
            account_role_name=account_role_name,
        )

    def create_sessions_for_account_and_account_master(self) -> Tuple[Session, Optional[Session]]:
        session = create_session_with_assume_role(self.account_id, self.account_role_name)
        self.logger.info(f"Successfully assume the role {self.account_role_name} for account id {self.account_id}")

        session_master = None
        if self.master_account_id and self.master_account_role_name:
            session_master = create_session_with_assume_role(self.master_account_id, self.master_account_role_name)

        if session_master:
            s3_master_client = session_master.client('s3')
            response = s3_master_client.list_buckets()
            self.logger.info(
                f"Successfully assume the role {self.master_account_role_name} for account id {self.master_account_id}"
            )

        return (session, session_master)

    def run(
        self,
    ):
        self.logger.info(
            f"Starting to analyzed AWS s3 for account id: {self.account_id}, master account id {self.master_account_id}"
        )
        session, session_master = self.create_sessions_for_account_and_account_master()
        analyzed_ctx = S3AuthzAnalyzerCtx.load(self.logger, session, session_master)
