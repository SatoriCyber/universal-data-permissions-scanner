"""Main module."""
from logging import Logger
from pathlib import Path
from typing import Optional, Set

from authz_analyzer import (
    BigQueryAuthzAnalyzer,
    MongoDBAtlasAuthzAnalyzer,
    MongoDBAuthzAnalyzer,
    PostgresAuthzAnalyzer,
    RedshiftAuthzAnalyzer,
    S3AuthzAnalyzer,
    SnowflakeAuthzAnalyzer,
)
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


# AWS S3 runner
def run_aws_s3(
    logger: Logger,
    output_format: OutputFormat,
    filename: str,
    target_account_id: str,
    additional_account_ids: Optional[Set[str]],
    account_role_name: str,
):
    writer = get_writer(filename, output_format)
    analyzer = S3AuthzAnalyzer.connect(
        target_account_id=target_account_id,
        additional_account_ids=additional_account_ids,
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
    analyzer = BigQueryAuthzAnalyzer.connect(
        logger=logger, project_id=project_id, output_path=output_path, output_format=output_format
    )
    analyzer.run()


def run_postgres(
    logger: Logger,
    username: str,
    password: str,
    host: str,
    dbname: str,
    output_format: OutputFormat,
    output_path: Path,
    port: int,
):
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
    analyzer = PostgresAuthzAnalyzer.connect(
        username=username,
        password=password,
        host=host,
        dbname=dbname,
        output_path=output_path,
        output_format=output_format,
        logger=logger,
        port=port,
    )
    analyzer.run()


def run_redshift(
    logger: Logger,
    username: str,
    password: str,
    host: str,
    dbname: str,
    output_format: OutputFormat,
    output_path: Path,
    port: int,
):
    """Run Redshift analyzer.

    Args:
        logger (Logger): Logger
        username (str): Postgres username
        password (str): Postgres password
        host (str): FQDN or IP of the postgres DB
        dbname (str): Postgres database name, for example postgres
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
        port (int): Redshift port
    """
    analyzer = RedshiftAuthzAnalyzer.connect(
        username=username,
        password=password,
        host=host,
        dbname=dbname,
        output_path=output_path,
        output_format=output_format,
        logger=logger,
        port=port,
    )
    analyzer.run()


def run_mongodb(
    logger: Logger,
    username: str,
    password: str,
    host: str,
    output_format: OutputFormat,
    output_path: Path,
    port: int,
):
    """Run MongoDB analyzer.

    Args:
        logger (Logger): Logger
        username (str): username
        password (str): password
        host (str): FQDN or IP of the MongoDB DB
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
        port (int): port
    """
    analyzer = MongoDBAuthzAnalyzer.connect(
        username=username,
        password=password,
        host=host,
        output_path=output_path,
        output_format=output_format,
        logger=logger,
        port=port,
    )
    analyzer.run()


def run_mongodb_atlas(
    logger: Logger,
    public_key: str,
    private_key: str,
    username: str,
    password: str,
    project_name: str,
    cluster_name: str,
    output_format: OutputFormat,
    output_path: Path,
):
    """Run MongoDB Atlas analyzer.

    Args:
        logger (Logger): Logger
        public_key (str): MongoDB Atlas public key, generated through the organization access manager
        private_key (str): MongoDB Atlas public key, generated through the organization access manager
        username (str): MongoDB cluster username
        password (str): MongoDB cluster password
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
    """
    analyzer = MongoDBAtlasAuthzAnalyzer.connect(
        public_key=public_key,
        private_key=private_key,
        db_user=username,
        db_password=password,
        project_name=project_name,
        cluster_name=cluster_name,
        output_path=output_path,
        output_format=output_format,
        logger=logger,
    )
    analyzer.run()
