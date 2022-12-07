from dataclasses import dataclass
from types import TracebackType
from typing import List, Optional, Tuple, Type
from unittest.mock import MagicMock


@dataclass
class MockCursor:
    user_grants: List[Tuple[str, str, str]]
    role_grants: List[Tuple[str, str, str, str, str]]

    def get(self):
        snowflake_mock = MagicMock(name="SnowflakeConnectionMock")
        fetchall = MagicMock(name="SnowflakFetchAllMock", side_effect=[self.user_grants, self.role_grants])

        snowflake_mock.fetchall = fetchall

        return snowflake_mock

    def __enter__(self):
        self.cursor = self.get()
        return self.cursor

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ):
        self.cursor.fetchall.assert_called()  # type: ignore
