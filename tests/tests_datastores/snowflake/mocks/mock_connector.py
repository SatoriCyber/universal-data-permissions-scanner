from dataclasses import dataclass
from types import TracebackType
from typing import List, Optional, Type
from unittest.mock import MagicMock


@dataclass
class MockConnector:
    user_grants: List[tuple[str, str]]
    role_grants: List[tuple[str, str]]
    role_resources: List[tuple[str, str, str]]

    def get(self):
        snowflake_mock = MagicMock(name="SnowflakeConnectionMock")
        execute_mock = MagicMock(
            name="SnowflakeExecuteMock", side_effect=[self.user_grants, self.role_grants, self.role_resources]
        )

        snowflake_mock.execute = execute_mock

        execute_mock.side_effect = [self.user_grants, self.role_grants, self.role_resources]

        return snowflake_mock

    def __enter__(self):
        self.connector = self.get()
        return self.connector

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ):
        self.connector.execute.assert_called()  # type: ignore
