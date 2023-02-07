from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Optional, Set, Union

# (vs-code) For python auto-complete please add this to your workspace setting.json file
# "python.autoComplete.extraPaths": [
#     "[PATH-TO-AUTHZ-ANALYZER]/authz_analyzer/datastores/aws/aws_ptrp_package/"
# ]
from aws_ptrp import AwsPtrp
from aws_ptrp.services import ServiceResourceType
from aws_ptrp.services.s3.s3_service import S3Service

from authz_analyzer.datastores.aws.analyzer.exporter import AWSAuthzAnalyzerExporter
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE


@dataclass
class AWSAuthzAnalyzer:
    exporter: AWSAuthzAnalyzerExporter
    logger: Logger
    target_account_id: str
    additional_account_ids: Optional[Set[str]]
    role_name: str
    external_id: Optional[str]

    @classmethod
    def connect(
        cls,
        target_account_id: str,
        role_name: str,
        external_id: Optional[str],
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
            role_name=role_name,
            external_id=external_id,
        )

    def run_s3(self):
        self._run(set([S3Service()]))

    def _run(
        self,
        resource_service_types: Set[ServiceResourceType],
    ):
        self.logger.info(
            "Starting to analyzed AWS for %s, target account id: %s, additional accounts: %s",
            resource_service_types,
            self.target_account_id,
            self.additional_account_ids,
        )
        aws_ptrp = AwsPtrp.load_from_role(
            logger=self.logger,
            role_name=self.role_name,
            external_id=self.external_id,
            resource_service_types_to_load=resource_service_types,
            target_account_id=self.target_account_id,
            additional_account_ids=self.additional_account_ids,
        )
        aws_ptrp.resolve_permissions(self.logger, self.exporter.export_entry_from_ptrp_line)
