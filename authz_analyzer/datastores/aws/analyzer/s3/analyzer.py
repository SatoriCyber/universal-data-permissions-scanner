"""Analyze authorization for S3.

"""
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union
from logging import Logger


# (vs-code) For python auto-complete please add this to your workspace setting.json file
# "python.autoComplete.extraPaths": [
#     "[PATH-TO-AUTHZ-ANALYZER]/authz_analyzer/datastores/aws/aws_ptrp_package/"
# ]
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.aws_authz_analyzer import AwsAuthzAnalyzer
from aws_ptrp.services.s3.s3_service import S3ServiceType
from aws_ptrp.services.assume_role.assume_role_service import AssumeRoleServiceType
from aws_ptrp.utils.create_session import create_session_with_assume_role

from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE


@dataclass
class S3AuthzAnalyzer:
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
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
    ):
        if logger is None:
            logger = get_logger(False)

        writer = get_writer(filename=output_path, output_format=output_format)

        return cls(
            logger=logger,
            writer=writer,
            account_id=account_id,
            account_role_name=account_role_name,
        )

    def run(
        self,
    ):
        self.logger.info("Starting to analyzed AWS s3 for account id: %s", self.account_id)
        session = create_session_with_assume_role(self.account_id, self.account_role_name)
        self.logger.info("Successfully assume the role %s for account id %s", self.account_role_name, self.account_id)
        iam_entities = IAMEntities.load(self.logger, self.account_id, session)
        aws_authz_analyzer = AwsAuthzAnalyzer.load(
            self.logger, iam_entities, session, set([S3ServiceType(), AssumeRoleServiceType()])
        )
        aws_authz_analyzer.resolve_permissions(self.logger, self.writer.write_entry)