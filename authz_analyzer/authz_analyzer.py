"""Main module."""
from pathlib import Path

from authz_collectors.snowflake_collector.snowflake_collector import AuthZSnowflakeCollector
from authz_data_model.authz_data_model import AuthorizationModel
from authz_exporters import csv_exporter
from az_bigquery.analyzer import BigQueryAuthzAnalyzer
from model import ConsoleReporter, FileReporter, OutputFormat, JSONFormatter

collector = AuthZSnowflakeCollector.connect(
        username='jane@satoripoc.info',
        password='[PLACEHOLDER]',
        host='bra51996.snowflakecomputing.com',
        account='pda02239',
        warehouse='COMPUTE_WH',
        database='SNOWFLAKE',
        # schema='PUBLIC',
)
print("Connected successfully")
authz_model: AuthorizationModel = collector.get_authorization_model()
print("Starting to analyze")
csv_exporter.export(authz_model, Path("csv_mode.xslx"))

def run_snowflake():
    pass

def run_bigquery(logger, project_id: str, format: OutputFormat, filename: str):
    reporter = get_reporter(format, filename)
    analyzer = BigQueryAuthzAnalyzer(logger, reporter, project_id)
    analyzer.run()
    reporter.close()

def get_formatter(format: OutputFormat):
    return JSONFormatter()
        
def get_reporter(format: OutputFormat, filename: str):
    formatter = get_formatter(format)
    if filename is None:
        reporter = ConsoleReporter(formatter)
    else:
        reporter = FileReporter(filename, formatter)
    return reporter
