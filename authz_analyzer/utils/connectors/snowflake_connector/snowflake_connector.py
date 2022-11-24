from dataclasses import dataclass
from typing import Any

import snowflake.connector
from snowflake.connector import SnowflakeConnection
from snowflake.connector.cursor import SnowflakeCursor

from utils.connectors.base_connector import BaseConnector


@dataclass
class AuthZSnowflakeConnector(BaseConnector):
    connector: SnowflakeConnection
    cursor: SnowflakeCursor

    @classmethod
    def connect(cls, host: str, username: str, password: str, **kwargs: Any):
        connector = snowflake.connector.connect(  # type: ignore
            user=username, password=password, host=host, **kwargs
        )
        cursor = connector.cursor()
        return cls(connector=connector, cursor=cursor)

    def execute(self, command: str, **kwargs: Any) -> list[tuple[Any]]:
        cursor = self.cursor.execute(command=command, **kwargs)
        if cursor is None:
            raise BaseException("Cursor is none")  # TODO: better handle later
        return cursor.fetchall()  # type: ignore
