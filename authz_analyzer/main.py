"""Main module."""
from logging import Logger
from pathlib import Path

from authz_analyzer.datastores.bigquery.analyzer import BigQueryAuthzAnalyzer
from authz_analyzer.datastores.snowflake.analyzer import SnowflakeAuthzAnalyzer
from authz_analyzer.datastores.aws.services.s3.analyzer import S3AuthzAnalyzer
from authz_analyzer.datastores.postgres.analyzer import PostgresAuthzAnalyzer
from authz_analyzer.writers import OutputFormat, get_writer


def run_snowflake(
    logger: Logger,
    username: str,
    password: str,
    account: str,
    host: str,
    warehouse: str,
    output_format: OutputFormat,
    output_path: Path,
):
    """Run snowflake analyzer.

    Args:
        logger (Logger): Logger
        username (str): Username
        password (str): Password
        account (str): Snowflake account to analyzer
        host (str): Snowflake host
        warehouse (str): Warehouse
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
    """
    snowflake_analyzer = SnowflakeAuthzAnalyzer.connect(
        host=host,
        username=username,
        password=password,
        warehouse=warehouse,
        account=account,
        output_path=output_path,
        output_format=output_format,
        logger=logger,
    )
    snowflake_analyzer.run()


# S3 runner
def run_s3(
    logger: Logger,
    output_format: OutputFormat,
    filename: str,
    account_id: str,
    account_role_name: str,
):
    writer = get_writer(filename, output_format)
    analyzer = S3AuthzAnalyzer.connect(
        account_id=account_id,
        account_role_name=account_role_name,
        output_path=filename,
        output_format=output_format,
        logger=logger,
    )
    analyzer.run()
    writer.close()


def run_bigquery(logger: Logger, project_id: str, output_format: OutputFormat, output_path: str):
    """Run BigQuery analyzer.

    Args:
        logger (Logger): Logger
        project_id (str): BigQuery project ID to scan
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
    """
    analyzer = BigQueryAuthzAnalyzer.connect(logger=logger, project_id=project_id, output_path=output_path, output_format=output_format)
    analyzer.run()

def run_postgres(logger: Logger, username: str, password: str, host: str, dbname: str, output_format: OutputFormat, output_path: Path, port: int):
    """Run Postgres analyzer.

    Args:
        logger (Logger): Logger
        username (str): Postgres username
        password (str): Postgres password
        host (str): FQDN or IP of the postgres DB
        dbname (str): Postgres database name, for example postgres
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
        port (int): Postgres port
    """
    PostgresAuthzAnalyzer.connect(username=username, password=password, host=host, dbname=dbname, output_path=output_path, output_format=output_format, logger=logger, port=port)
