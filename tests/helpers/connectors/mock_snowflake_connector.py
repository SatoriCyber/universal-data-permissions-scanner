from unittest.mock import MagicMock


def get():
    mock = MagicMock(name="SnowflakeClient")
    # snowflake_connector = MagicMock(name="SnowflakeConnector")
    # snowflake_connection = MagicMock(name="SnowflakeConnection")
    # snowflake_cursor = MagicMock(name="SnowflakeCursor")

    # mock.connect = snowflake_connector
    # snowflake_connector.return_value = snowflake_connection
    # mock.cursor = snowflake_cursor
    return mock
