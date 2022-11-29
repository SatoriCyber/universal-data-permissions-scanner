"""Main module."""
import logging
import sys
from logging import Logger
from pathlib import Path
from typing import Any, Dict, Optional, Union

from authz_analyzer.datastores.base import BaseConnectParams
from authz_analyzer.datastores.bigquery.analyzer import BigQueryAuthzAnalyzer
from authz_analyzer.datastores.snowflake import SnowflakeAuthzAnalyzer, SnowflakeConnectionParameters
from authz_analyzer.writers import OutputFormat
from authz_analyzer.writers.csv_writer import CSVWriter
from authz_analyzer.writers.multi_json_exporter import MultiJsonWriter


def get_logger(debug: bool):
    logger = logging.getLogger('authz-analyzer')
    if debug:
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    return logger


def get_writer(filename: Union[Path, str], format: OutputFormat):
    fh = sys.stdout if filename is None else open(filename, 'w', encoding="utf=8")
    if format == OutputFormat.MultiJson:
        return MultiJsonWriter(fh)
    elif format == OutputFormat.Csv:
        return CSVWriter(fh)
    raise BaseException("Output format not support")  # TODO: Better handle


def run_snowflake(
    logger: Logger,
    username: str,
    password: str,
    account: str,
    host: str,
    warehouse: str,
    format: OutputFormat,
    filename: str,
):
    snowflake_params = SnowflakeConnectionParameters(
        host=host, username=username, password=password, warehouse=warehouse, account=account
    )
    writer = get_writer(filename, format=format)
    writer.write_header()
    snowflake_analyzer = SnowflakeAuthzAnalyzer.connect(snowflake_params, writer=writer, logger=logger)
    snowflake_analyzer.run()
    writer.close()


# BigQuery runner
def run_bigquery(logger: Logger, project_id: str, format: OutputFormat, filename: str):
    writer = get_writer(filename, format)
    writer.write_header()
    analyzer = BigQueryAuthzAnalyzer.connect(logger=logger, writer=writer, project_id=project_id)
    analyzer.run()
    writer.close()


class AuthzAnalyzer:
    @staticmethod
    def run(
        db_params: BaseConnectParams,
        output_path: Union[Path, str] = Path.cwd() / "authz-analyzer-export",
        output_format: OutputFormat = OutputFormat.Csv,
        logger: Optional[Logger] = None,
        **queries_kwargs: Dict[str, Any],
    ):
        if logger is None:
            logger = get_logger(False)
        writer = get_writer(output_path, output_format)
        writer.write_header()

        if isinstance(db_params, SnowflakeConnectionParameters):
            snowflake_analyzer = SnowflakeAuthzAnalyzer.connect(db_params, writer=writer, logger=logger)
            snowflake_analyzer.run()
            writer.close()
        writer.close()
