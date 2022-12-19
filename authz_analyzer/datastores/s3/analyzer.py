"""Analyze authorization for S3.

"""
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from authz_analyzer.utils.aws.create_session import create_session_with_assume_role
from authz_analyzer.utils.aws.account_resources import AwsAccountResources
from authz_analyzer.utils.aws.s3.bucket import S3ServiceType
from authz_analyzer.utils.aws.aws_authz_analyzer import AwsAuthzAnalyzer
from authz_analyzer.datastores.base import BaseAuthzAnalyzer
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE


@dataclass
class S3AuthzAnalyzer(BaseAuthzAnalyzer):
    writer: BaseWriter
    logger: Logger
    account_id: str
    account_role_name: str

    @classmethod
    def connect(
        cls,
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
            account_id=account_id,
            account_role_name=account_role_name,
        )

    def run(
        self,
    ):
        self.logger.info(f"Starting to analyzed AWS s3 for account id: {self.account_id}")
        session = create_session_with_assume_role(self.account_id, self.account_role_name)
        self.logger.info(f"Successfully assume the role {self.account_role_name} for account id {self.account_id}")
        analyzed_ctx = AwsAuthzAnalyzer.load(self.logger, self.account_id, session, set([S3ServiceType()]))
