from authz_analyzer.authz_collectors.snowflake_collector.snowflake_collector import AuthZSnowflakeCollector
from authz_analyzer.utils.connectors.snowflake_connector.snowflake_connector import AuthZSnowflakeConnector
# from authz_analyzer.authz_exporters import csv_exporter

def test_get_users_grants():
    connector = AuthZSnowflakeConnector.connect(
        username='omer.shtivi@satoricyber.com',
        password='[PLACEHOLDER]',
        host='pda02239.us-east-1.snowflakecomputing.com',
        account='pda02239',
        warehouse='COMPUTE_WH',
        database='SNOWFLAKE',
        # schema='PUBLIC',
    )
    # collector = AuthZSnowflakeCollector(connector=connector)
    # users = collector._get_role_to_resource_mapping()
    print("i'm here to stay!")
