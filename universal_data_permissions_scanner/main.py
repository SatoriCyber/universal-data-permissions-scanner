"""Main module."""

from logging import Logger
from pathlib import Path
from typing import Any, List, Optional

from universal_data_permissions_scanner import (
    AwsAssumeRoleInput,
    AWSAuthzAnalyzer,
    BigQueryAuthzAnalyzer,
    MongoDBAtlasAuthzAnalyzer,
    MongoDBAuthzAnalyzer,
    PostgresAuthzAnalyzer,
    RedshiftAuthzAnalyzer,
    SnowflakeAuthzAnalyzer,
)
from universal_data_permissions_scanner.writers import OutputFormat, open_writer

from universal_data_permissions_scanner.datastores.databricks.analyzer import DatabricksAuthzAnalyzer
from universal_data_permissions_scanner.datastores.databricks import Authentication


def run_snowflake(
    logger: Logger,
    username: str,
    password: Optional[str],
    account: str,
    warehouse: Optional[str],
    output_format: OutputFormat,
    output_path: Path,
    rsa_key: Optional[str],
    rsa_pass: Optional[str],
    **kwargs: Any,
) -> None:
    """Run snowflake analyzer.

    Args:
        logger (Logger): Logger
        username (str): Username
        password (str): Password
        account (str): Snowflake account to analyzer
        warehouse (str): Warehouse
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
        kwargs:
            host (str): Snowflake host
    """
    with open_writer(output_path, output_format) as writer:
        snowflake_analyzer = SnowflakeAuthzAnalyzer.connect(
            username=username,
            password=password,
            warehouse=warehouse,
            account=account,
            logger=logger,
            rsa_key=rsa_key,
            rsa_pass=rsa_pass,
            writer=writer,
            kwargs=kwargs,
        )
        snowflake_analyzer.run()


# AWS S3 runner
def run_aws_s3(
    logger: Logger,
    output_format: OutputFormat,
    output_path: str,
    target_account: AwsAssumeRoleInput,
    additional_accounts: Optional[List[AwsAssumeRoleInput]] = None,
) -> None:
    with open_writer(output_path, output_format) as writer:
        analyzer = AWSAuthzAnalyzer.connect(
            target_account=target_account,
            additional_accounts=additional_accounts,
            logger=logger,
            writer=writer,
        )
        analyzer.run_s3()


def run_bigquery(logger: Logger, project_id: str, output_format: OutputFormat, output_path: str) -> None:
    """Run BigQuery analyzer.

    Args:
        logger (Logger): Logger
        project_id (str): BigQuery project ID to scan
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
    """
    with open_writer(output_path, output_format) as writer:
        analyzer = BigQueryAuthzAnalyzer.connect(logger=logger, project_id=project_id, writer=writer)
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
) -> None:
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
    with open_writer(output_path, output_format) as writer:
        analyzer = PostgresAuthzAnalyzer.connect(
            username=username,
            password=password,
            host=host,
            dbname=dbname,
            logger=logger,
            port=port,
            writer=writer,
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
) -> None:
    """Run Redshift analyzer.

    Args:
        logger (Logger): Logger
        username (str): Redshift username
        password (str): Redshift password
        host (str): FQDN or IP of the redshift DB
        dbname (str): Redshift database name, for example dev
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
        port (int): Redshift port
    """
    with open_writer(output_path, output_format) as writer:
        analyzer = RedshiftAuthzAnalyzer.connect(
            username=username,
            password=password,
            host=host,
            dbname=dbname,
            logger=logger,
            port=port,
            writer=writer,
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
    ssl: bool,
) -> None:
    """Run MongoDB analyzer.

    Args:
        logger (Logger): Logger
        username (str): username
        password (str): password
        host (str): FQDN or IP of the MongoDB DB
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
        port (int): port
        ssl(bool): use ssl
    """
    with open_writer(output_path, output_format) as writer:
        analyzer = MongoDBAuthzAnalyzer.connect(
            username=username,
            password=password,
            host=host,
            logger=logger,
            port=port,
            ssl=ssl,
            writer=writer,
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
) -> None:
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
    with open_writer(output_path, output_format) as writer:
        analyzer = MongoDBAtlasAuthzAnalyzer.connect(
            public_key=public_key,
            private_key=private_key,
            db_user=username,
            db_password=password,
            project_name=project_name,
            cluster_name=cluster_name,
            writer=writer,
            logger=logger,
        )
        analyzer.run()


def run_databricks(
    logger: Logger,
    host: str,
    authentication: Authentication,
    account_id: str,
    output_format: OutputFormat,
    output_path: Path,
) -> None:
    """Run Databricks analyzer.

    Args:
        logger (Logger): Logger
        host (str): workspace host, e.g. https://<workspace>.cloud.databricks.com
        key (str): Databricks API key
        output_format (OutputFormat): Output format, CSV or JSON
        output_path (str): Where to write the output
        authentication: Authentication method
    """
    with open_writer(output_path, output_format) as writer:
        analyzer = DatabricksAuthzAnalyzer.connect(
            host=host,
            authentication=authentication,
            account_id=account_id,
            logger=logger,
            writer=writer,
        )
        analyzer.run()
