from dataclasses import dataclass
from types import TracebackType
from typing import List, NamedTuple, Optional, Type
from unittest.mock import MagicMock


class Role(NamedTuple):
    username: str
    superuser: bool
    role: Optional[str]
    login: bool


class RoleGrant(NamedTuple):
    table_name: str
    schema: str
    type: str
    owner: str
    relacl: Optional[str]


class Table(NamedTuple):
    table_catalog: str
    table_schema: str
    table_name: str


@dataclass
class PostgresMockCursor:
    roles: List[Role]
    role_grants: List[RoleGrant]
    all_tables: List[Table]

    def get(self):
        postgres_mock = MagicMock(name="PostgresConnectionMock")
        fetchall = MagicMock(name="PostgresFetchAllMock", side_effect=[self.roles, self.role_grants, self.all_tables])

        postgres_mock.fetchall = fetchall

        return postgres_mock

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
