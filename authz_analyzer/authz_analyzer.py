"""Main module."""
from pathlib import Path

from authz_collectors.snowflake_collector.snowflake_collector import AuthZSnowflakeCollector
from authz_data_model.authz_data_model import AuthorizationModel
from authz_exporters import csv_exporter
from az_bigquery.analyzer import BigQueryAuthzAnalyzer
import sys
from writers import OutputFormat, JSONWriter, CSVWriter

# Snowflake runner
def run_snowflake(logger, username: str, password: str, account: str, host: str, warehouse: str, filename: str):
    collector = AuthZSnowflakeCollector.connect(
        username=username,
        password=password,
        account=account,
        host=host,
        warehouse=warehouse,
        database='SNOWFLAKE'
    )
    logger.debug("Connected successfully")
    authz_model: AuthorizationModel = collector.get_authorization_model()
    logger.debug("Starting to analyze")
    csv_exporter.export(authz_model, Path(filename))

# BigQuery runner
def run_bigquery(logger, project_id: str, format: OutputFormat, filename: str):
    writer = get_writer(filename, format)
    writer.write_header()
    analyzer = BigQueryAuthzAnalyzer(logger, writer, project_id)
    analyzer.run()
    writer.close()

def get_writer(filename: str, format: OutputFormat):
    fh = sys.stdout if filename is None else open(filename, 'w')
    if format == OutputFormat.JSON:
        return JSONWriter(fh)
    elif format == OutputFormat.CSV:
        return CSVWriter(fh)
    return None
        