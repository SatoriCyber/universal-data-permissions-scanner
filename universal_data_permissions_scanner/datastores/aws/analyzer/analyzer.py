from collections import namedtuple
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import List, Optional, Set, Union

# (vs-code) For python auto-complete please add this to your workspace setting.json file
# "python.autoComplete.extraPaths": [
#     "[PATH-TO-AUTHZ-ANALYZER]/authz_analyzer/datastores/aws/aws_ptrp_package/"
# ]
from aws_ptrp import AwsAssumeRole, AwsPtrp
from aws_ptrp.services import ServiceResourceType
from aws_ptrp.services.s3.s3_service import S3Service

from universal_data_permissions_scanner.datastores.aws.analyzer.exporter import AWSAuthzAnalyzerExporter
from universal_data_permissions_scanner.utils.logger import get_logger
from universal_data_permissions_scanner.writers import BaseWriter, OutputFormat, get_writer
from universal_data_permissions_scanner.writers.base_writers import DEFAULT_OUTPUT_FILE

AwsAssumeRoleInput = namedtuple('AwsAssumeRoleInput', ['role_arn', 'external_id'])


@dataclass
class AWSAuthzAnalyzer:
    exporter: AWSAuthzAnalyzerExporter
    logger: Logger
    target_account: AwsAssumeRole
    additional_accounts: Optional[List[AwsAssumeRole]] = None

    @classmethod
    def connect(
        cls,
        target_account: AwsAssumeRoleInput,
        additional_accounts: Optional[List[AwsAssumeRoleInput]] = None,
        logger: Optional[Logger] = None,
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
    ):
        if logger is None:
            logger = get_logger(False)

        writer: BaseWriter = get_writer(filename=output_path, output_format=output_format)
        aws_exporter = AWSAuthzAnalyzerExporter(writer)
        target_account_assume_role = AwsAssumeRole(
            role_arn=target_account.role_arn,
            external_id=target_account.external_id,
        )
        if additional_accounts:
            additional_accounts_assume_role: Optional[List[AwsAssumeRole]] = [
                AwsAssumeRole(
                    role_arn=additional_account.role_arn,
                    external_id=additional_account.external_id,
                )
                for additional_account in additional_accounts
            ]
        else:
            additional_accounts_assume_role = None
        return cls(
            logger=logger,
            exporter=aws_exporter,
            target_account=target_account_assume_role,
            additional_accounts=additional_accounts_assume_role,
        )

    def run_s3(self):
        self._run(set([S3Service()]))

    def _run(
        self,
        resource_service_types: Set[ServiceResourceType],
    ):
        self.logger.info(
            "Starting to analyzed AWS for %s, target account: %s, additional accounts: %s",
            resource_service_types,
            self.target_account,
            self.additional_accounts,
        )
        aws_ptrp = AwsPtrp.load_from_role(
            logger=self.logger,
            resource_service_types_to_load=resource_service_types,
            target_account=self.target_account,
            additional_accounts=self.additional_accounts,
        )
        aws_ptrp.resolve_permissions(self.logger, self.exporter.export_entry_from_ptrp_line)
