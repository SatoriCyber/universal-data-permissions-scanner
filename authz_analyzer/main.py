"""Main module."""
from logging import Logger

from authz_analyzer.datastores.bigquery.analyzer import BigQueryAuthzAnalyzer
from authz_analyzer.datastores.snowflake.analyzer import SnowflakeAuthzAnalyzer
from authz_analyzer.writers import OutputFormat, get_writer


def run_snowflake(
    logger: Logger,
    username: str,
    password: str,
    account: str,
    host: str,
    warehouse: str,
    output_format: OutputFormat,
    filename: str,
):
    snowflake_analyzer = SnowflakeAuthzAnalyzer.connect(
        host=host,
        username=username,
        password=password,
        warehouse=warehouse,
        account=account,
        output_path=filename,
        output_format=output_format,
        logger=logger,
    )
    snowflake_analyzer.run()


# BigQuery runner
def run_bigquery(logger: Logger, project_id: str, output_format: OutputFormat, filename: str):
    writer = get_writer(filename, output_format)
    writer.write_header()
    analyzer = BigQueryAuthzAnalyzer.connect(logger=logger, writer=writer, project_id=project_id)
    analyzer.run()
    writer.close()
