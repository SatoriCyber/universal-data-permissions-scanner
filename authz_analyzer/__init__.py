"""Top-level package for authz-analyzer."""

__author__ = """SatoriCyber"""
__email__ = 'omer.shtivi@satoricyber.com'
__version__ = '3.0.1'

from authz_analyzer.datastores.bigquery.analyzer import BigQueryAuthzAnalyzer
from authz_analyzer.datastores.postgres.analyzer import PostgresAuthzAnalyzer
from authz_analyzer.datastores.snowflake.analyzer import SnowflakeAuthzAnalyzer
