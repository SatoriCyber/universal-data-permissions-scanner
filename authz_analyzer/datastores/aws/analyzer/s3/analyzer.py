"""Analyze authorization for S3.

"""
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Optional, Set, Union

# (vs-code) For python auto-complete please add this to your workspace setting.json file
# "python.autoComplete.extraPaths": [
#     "[PATH-TO-AUTHZ-ANALYZER]/authz_analyzer/datastores/aws/aws_ptrp_package/"
# ]
from aws_ptrp import AwsPtrp
from aws_ptrp.services.s3.s3_service import S3Service

from authz_analyzer.datastores.aws.analyzer.exporter import AWSAuthzAnalyzerExporter
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE


@dataclass
class S3AuthzAnalyzer:
    exporter: AWSAuthzAnalyzerExporter
    logger: Logger
    target_account_id: str
    additional_account_ids: Optional[Set[str]]
    account_role_name: str

    @classmethod
    def connect(
        cls,
        target_account_id,
        account_role_name,
        additional_account_ids: Optional[Set[str]] = None,
        logger: Optional[Logger] = None,
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
    ):
        if logger is None:
            logger = get_logger(False)

        writer: BaseWriter = get_writer(filename=output_path, output_format=output_format)
        aws_exporter = AWSAuthzAnalyzerExporter(writer)
        return cls(
            logger=logger,
            exporter=aws_exporter,
            target_account_id=target_account_id,
            additional_account_ids=additional_account_ids,
            account_role_name=account_role_name,
        )

    def run(
        self,
    ):
        self.logger.info(
            "Starting to analyzed AWS s3 for target account id: %s, additional accounts: %s",
            self.target_account_id,
            self.additional_account_ids,
        )
        aws_ptrp = AwsPtrp.load_from_role(
            self.logger, self.account_role_name, set([S3Service()]), self.target_account_id, self.additional_account_ids
        )
        aws_ptrp.resolve_permissions(self.logger, self.exporter.export_entry_from_ptrp_line)
