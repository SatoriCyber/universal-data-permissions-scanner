"""Main module."""
from pathlib import Path

from authz_collectors.snowflake_collector.snowflake_collector import AuthZSnowflakeCollector
from authz_data_model.authz_data_model import AuthorizationModel
from authz_exporters import csv_exporter
from az_bigquery.analyzer import BigQueryAuthzAnalyzer

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

if __name__ == '__main__':
    project_id = "dev-gcp-europe-central2-yoav"
    analyzer = BigQueryAuthzAnalyzer(project_id)
    analyzer.run()

