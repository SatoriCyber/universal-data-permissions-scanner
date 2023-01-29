from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, NamedTuple, Sequence, Tuple, Union
from unittest.mock import MagicMock, call
import pytest

from redshift_connector import Cursor  # type: ignore
from authz_analyzer.datastores.redshift.analyzer import RedshiftAuthzAnalyzer
from authz_analyzer.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)

from tests.mocks.mock_writers import MockWriter


class IdentityDB(NamedTuple):
    """identities.sql response"""

    identity_id: str
    identity_name: str
    identity_type: str
    granted_identity_id: str
    granted_identity_name: str
    granted_identity_type: str
    is_admin: bool


class IdentitiesPrivileges(NamedTuple):
    """identities_privileges.sql response"""

    grantor: str
    identity: str
    schema_name: str
    table_name: str
    db_permission: str

class Table(NamedTuple):
    """all_tables.sql response"""

    schema_name: str
    table_name: str
    table_type: str

@dataclass
class RedshiftMockService:
    mocked_service: MagicMock
    cursors: List[MagicMock] = field(default_factory=list)
    identities: Dict[MagicMock, List[IdentityDB]] = field(default_factory=dict)
    identities_privileges: Dict[MagicMock, List[IdentitiesPrivileges]] = field(default_factory=dict)
    all_tables: Dict[MagicMock, List[Table]] = field(default_factory=dict)

    @classmethod
    def new(cls):
        mocked_service = MagicMock(name="RedshiftMockService")
        instance = cls(mocked_service)
        mocked_get_rows = MagicMock(name="RedshiftServiceGetRows", side_effect=instance._get_rows)

        mocked_service.get_rows = mocked_get_rows
        return instance

    def add_database(
        self, database_name: str, identities: List[IdentityDB], identities_privileges: List[IdentitiesPrivileges], all_tables: List[Table]
    ) -> None:
        """Add a database to the mocked service along with its identities and privileges.

        Args:
            database_name (str): Name of the database
            identities (List[IdentityDB]): Identities to roles
            identities_privileges (List[str]): Identities privileges
        """
        mocked_cursor = MagicMock(name=f"RedshiftServiceCursor{database_name}", spec=Cursor) #type: ignore
        mocked_connection = MagicMock(name=f"RedshiftServiceConnection{database_name}") #type: ignore
        mocked_connection._database = database_name
        mocked_cursor.connection = mocked_connection
        self.cursors.append(mocked_cursor)
        self.identities[mocked_cursor] = identities
        self.identities_privileges[mocked_cursor] = identities_privileges
        self.all_tables[mocked_cursor] = all_tables

    def get(self):
        self.mocked_service.cursors = self.cursors
        return self.mocked_service

    def _get_rows(self, redshift_cursor: MagicMock, command_name: Path) -> Sequence[Tuple[Union[str, bool], ...]]:
        identities = self.identities[redshift_cursor]
        identities_privileges = self.identities_privileges[redshift_cursor]
        if command_name == Path("identities.sql"):
            return identities
        if command_name == Path("identities_privileges.sql"):
            return identities_privileges
        if command_name == Path("all_tables.sql"):
            return self.all_tables[redshift_cursor]
        raise Exception(f"Command {command_name} not mocked")


def generate_authz_entry(
    asset_name: List[str], path: List[AuthzPathElement], user_id: str, username: str, permission: PermissionLevel
):
    asset = Asset(asset_name, AssetType.TABLE)
    identity = Identity(id=user_id, name=username, type=IdentityType.USER)
    return call(AuthzEntry(asset=asset, path=path, identity=identity, permission=permission))


@pytest.mark.parametrize(
    "database_name,identities, identities_privileges, all_tables, expected_writes",
    [
        ("db1", [], [], [], []),  # test 1 - empty
        ("db1", [IdentityDB("user_id_1", "user_1", "USER", "", "", "", False)], [], [], []),  # test 2 - user with no role
        (  # test 3 - user with direct access
            "db1",
            [IdentityDB("user_id_1", "user_1", "USER", "", "", "", False)],
            [IdentitiesPrivileges("UNKNOWN", "user_id_1", "schema_1", "table_1", "SELECT")], [],
            [
                generate_authz_entry(
                    ["db1", "schema_1", "table_1"],
                    [AuthzPathElement("user_id_1", "user_1", AuthzPathElementType.USER, "", ["SELECT"])],
                    "user_id_1",
                    "user_1",
                    PermissionLevel.READ,
                )
            ],
        ),
        (  # test 4 - user with role and privs
            "db1",
            [IdentityDB("user_id_1", "user_1", "USER", "ROLE_1_ID", "ROLE_1", "ROLE", False)],
            [IdentitiesPrivileges("UNKNOWN", "ROLE_1_ID", "schema_1", "table_1", "SELECT")], [],
            [
                generate_authz_entry(
                    ["db1", "schema_1", "table_1"],
                    [AuthzPathElement("ROLE_1_ID", "ROLE_1", AuthzPathElementType.ROLE, "", ["SELECT"])],
                    "user_id_1",
                    "user_1",
                    PermissionLevel.READ,
                )
            ],
        ),
    ],
    ids=["empty", "user with no privs", "user with direct access", "user with role and privs"],
)
def test_users(
    database_name: str,
    identities: List[IdentityDB],
    identities_privileges: List[IdentitiesPrivileges],
    expected_writes: List[AuthzEntry],
    all_tables: List[Table],
):
    print(identities, identities_privileges)
    mocked_writer = MockWriter.new()
    mock_service = RedshiftMockService.new()
    mock_service.add_database(database_name, identities, identities_privileges, all_tables)
    _call_analyzer(mock_service, mocked_writer)
    if len(expected_writes) != 0:
        mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore
    else:
        mocked_writer.assert_write_entry_not_called()


def _call_analyzer(service: RedshiftMockService, mocked_writer: MockWriter):
    analyzer = RedshiftAuthzAnalyzer(service=service.get(), cursors=service.cursors, logger=MagicMock(), writer=mocked_writer.get())  # type: ignore
    analyzer.run()
