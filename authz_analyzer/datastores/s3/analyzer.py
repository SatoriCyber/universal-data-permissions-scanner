"""Analyze authorization for S3.

"""

import json
from boto3 import Session
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from authz_analyzer.utils.aws.create_session import create_session_with_assume_role
from authz_analyzer.utils.aws.s3.bucket_to_analyzed import get_buckets, S3BucketToAnalyzed
from authz_analyzer.utils.aws.iam.iam_users import get_iam_users
from authz_analyzer.datastores.base import BaseAuthzAnalyzer
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE


@dataclass
class S3AuthzAnalyzerCtx:
    session: Session
    session_master: Optional[Session]
    buckets_to_analyzed: Dict[str, S3BucketToAnalyzed]


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

    def run(
        self,
    ):
        self.logger.info(
            f"Starting to analyzed AWS s3 for account id: {self.account_id}, master account id {self.master_account_id}"
        )
        session = create_session_with_assume_role(self.account_id, self.account_role_name)
        self.logger.info(f"Successfully assume the role {self.account_role_name} for account id {self.account_id}")
        
        session_master = None
        if self.master_account_id and self.master_account_role_name:
            session_master = create_session_with_assume_role(self.master_account_id, self.master_account_role_name)

        if session_master:
            s3_master_client = session_master.client('s3')
            response = s3_master_client.list_buckets()
            self.logger.info(f"Successfully assume the role {self.master_account_role_name} for account id {self.master_account_id}")
        
        # Get the buckets to analyzed
        buckets_to_analyzed = get_buckets(session)
        ctx = S3AuthzAnalyzerCtx(
            session=session, session_master=session_master, buckets_to_analyzed=buckets_to_analyzed
        )
        self.logger.info(f"Got buckets to analyzed: {buckets_to_analyzed.keys()}")
        
        # Get the iam users 
        iam_users = get_iam_users(session)
        
