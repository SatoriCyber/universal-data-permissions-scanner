from dataclasses import dataclass
from typing import Any, List, Tuple

import snowflake.connector
from snowflake.connector import SnowflakeConnection
from snowflake.connector.cursor import SnowflakeCursor

from authz_analyzer.datastores.base import BaseConnector, BaseConnectParams
from authz_analyzer.datastores.snowflake.params import SnowflakeConnectionParameters


@dataclass
class SnowflakeConnector(BaseConnector):
    connector: SnowflakeConnection
    cursor: SnowflakeCursor

    @classmethod
    def connect(cls, params: BaseConnectParams) -> BaseConnector:
        if not isinstance(params, SnowflakeConnectionParameters):
            raise BaseException(
                "Expecting snowflake params to be SnowflakeConnectionParameters"
            )  # T ODO: Better exceptions
        connector = snowflake.connector.connect(  # type: ignore
            user=params.username,
            password=params.password,
            host=params.host,
            account=params.account,
            warehouse=params.warehouse,
            **params.snowflake_connection_kwargs,
        )
        cursor = connector.cursor()
        return cls(connector=connector, cursor=cursor)

    def execute(self, command: str, **kwargs: Any) -> List[Tuple[Any]]:
        cursor = self.cursor.execute(command=command, **kwargs)
        if cursor is None:
            raise BaseException("Cursor is none")  # TODO: better handle later
        return cursor.fetchall()  # type: ignore
