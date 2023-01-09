"""Top-level package for authz-analyzer."""

__author__ = """SatoriCyber"""
__email__ = 'omer.shtivi@satoricyber.com'
__version__ = '3.5.0'

from authz_analyzer.datastores.bigquery.analyzer import BigQueryAuthzAnalyzer  # type: ignore
from authz_analyzer.datastores.postgres.analyzer import PostgresAuthzAnalyzer  # type: ignore
from authz_analyzer.datastores.redshift.analyzer import RedshiftAuthzAnalyzer  # type: ignore
from authz_analyzer.datastores.snowflake.analyzer import SnowflakeAuthzAnalyzer  # type: ignore
from authz_analyzer.datastores.aws.services.s3.analyzer import S3AuthzAnalyzer  # type: ignore
