"""Top-level package for authz-analyzer."""

__author__ = """SatoriCyber"""
__email__ = 'omer.shtivi@satoricyber.com'
__version__ = '4.7.0'

from authz_analyzer.datastores.aws.analyzer import AWSAuthzAnalyzer  # type: ignore
from authz_analyzer.datastores.aws.analyzer.redshift.analyzer import RedshiftAuthzAnalyzer  # type: ignore
from authz_analyzer.datastores.bigquery.analyzer import BigQueryAuthzAnalyzer  # type: ignore
from authz_analyzer.datastores.mongodb.analyzer import MongoDBAuthzAnalyzer  # type: ignore
from authz_analyzer.datastores.mongodb.atlas.analyzer import MongoDBAtlasAuthzAnalyzer  # type: ignore
from authz_analyzer.datastores.postgres.analyzer import PostgresAuthzAnalyzer  # type: ignore
from authz_analyzer.datastores.snowflake.analyzer import SnowflakeAuthzAnalyzer  # type: ignore
