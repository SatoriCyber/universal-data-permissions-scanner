"""Top-level package for authz-analyzer."""

__author__ = """SatoriCyber"""
__email__ = 'contact@satoricyber.com'
__version__ = '0.1.24'

from universal_data_permissions_scanner.datastores.aws.analyzer import AwsAssumeRoleInput, AWSAuthzAnalyzer  # type: ignore
from universal_data_permissions_scanner.datastores.aws.analyzer.redshift.analyzer import RedshiftAuthzAnalyzer  # type: ignore
from universal_data_permissions_scanner.datastores.bigquery.analyzer import BigQueryAuthzAnalyzer  # type: ignore
from universal_data_permissions_scanner.datastores.databricks.analyzer import DatabricksAuthzAnalyzer  # type: ignore
from universal_data_permissions_scanner.datastores.mongodb.analyzer import MongoDBAuthzAnalyzer  # type: ignore
from universal_data_permissions_scanner.datastores.mongodb.atlas.analyzer import MongoDBAtlasAuthzAnalyzer  # type: ignore
from universal_data_permissions_scanner.datastores.postgres.analyzer import PostgresAuthzAnalyzer  # type: ignore
from universal_data_permissions_scanner.datastores.snowflake.analyzer import SnowflakeAuthzAnalyzer  # type: ignore
