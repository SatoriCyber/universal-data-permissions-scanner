from typing import List, Optional, Tuple
from unittest.mock import MagicMock
from authz_analyzer import PostgresAuthzAnalyzer
from authz_analyzer.models.model import (
    AuthzEntry,
    AuthzPathElement,
    PermissionLevel,
    Identity,
    Asset,
    AuthzPathElementType,
    IdentityType,
    AssetType,
)

from tests.tests_datastores.postgres.mocks.postgres_mock_connector import PostgresMockCursor
from tests.mocks.mock_writers import MockWriter

ALL_TABLES = [("db1.schema1.table3",)]
USER_ONE_ROLE_ONE: List[Tuple[str, bool, Optional[str], bool]] = [("user_1", False, "role_1", True)]
USER_ONE_DIRECT_ACCESS = [("grantor", "user_1", "db1.schema1.table1", "SELECT")]
NO_ROLES_GRANTS = [("", "", "", "")]
ROLE_ONE_GRANT_TABLE_ONE = [("grantor", "role_1", "db1.schema1.table1", "SELECT")]
ROLE_TWO_GRANT_TABLE_ONE = [("grantor", "role_2", "db1.schema1.table1", "SELECT")]
USER_ONE_ROLE_ONE_ROLE_2: List[Tuple[str, bool, Optional[str], bool]] = [
    ("user_1", False, "role_1", True),
    ("role_1", False, "role_2", False),
]

THREE_ROLES_GRANTS: List[Tuple[str, bool, Optional[str], bool]] = [
    ("user_1", False, "role_1", True),
    ("role_1", False, "role_2", False),
    ("role_2", False, "role_3", False),
]
ROLE_THREE_GRANT_TABLE_ONE = [("grantor", "role_3", "db1.schema1.table1", "SELECT")]

USER_ONE_SUPER: List[Tuple[str, bool, Optional[str], bool]] = [("user_1", True, None, True)]


def test_user_role_no_role_grants():
    """Test user with role, but role don't have permissions"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(USER_ONE_ROLE_ONE, NO_ROLES_GRANTS, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_not_called()


def test_user_role_with_grant():
    """Test user with role and grant"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(USER_ONE_ROLE_ONE, ROLE_ONE_GRANT_TABLE_ONE, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[AuthzPathElement(id="role_1", name="role_1", type=AuthzPathElementType.ROLE, note="")],
            permission=PermissionLevel.READ,
            asset=Asset(name="db1.schema1.table1", type=AssetType.TABLE),
        )
    )


def test_user_role_to_role_grant():
    """Test user with role1, role1 mapped to role2 which doesn't have grants"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(USER_ONE_ROLE_ONE_ROLE_2, NO_ROLES_GRANTS, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_not_called()


def test_user_role_to_role_with_grant():
    """Test user with role1, role1 mapped to role2, role_2 has grant"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(USER_ONE_ROLE_ONE_ROLE_2, ROLE_TWO_GRANT_TABLE_ONE, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[
                AuthzPathElement(id="role_1", name="role_1", type=AuthzPathElementType.ROLE, note=""),
                AuthzPathElement(id="role_2", name="role_2", type=AuthzPathElementType.ROLE, note=""),
            ],
            permission=PermissionLevel.READ,
            asset=Asset(name="db1.schema1.table1", type=AssetType.TABLE),
        )
    )


def test_user_three_roles_with_grant():
    """Test user with role1, role1 mapped to role2, role_2 maps to role_3, role_3 has grant"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(USER_ONE_ROLE_ONE_ROLE_2, ROLE_TWO_GRANT_TABLE_ONE, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[
                AuthzPathElement(id="role_1", name="role_1", type=AuthzPathElementType.ROLE, note=""),
                AuthzPathElement(id="role_2", name="role_2", type=AuthzPathElementType.ROLE, note=""),
            ],
            permission=PermissionLevel.READ,
            asset=Asset(name="db1.schema1.table1", type=AssetType.TABLE),
        )
    )


def test_user_role_with_direct_grant():
    """Test user with direct access to table"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(THREE_ROLES_GRANTS, ROLE_THREE_GRANT_TABLE_ONE, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[
                AuthzPathElement(id="role_1", name="role_1", type=AuthzPathElementType.ROLE, note=""),
                AuthzPathElement(id="role_2", name="role_2", type=AuthzPathElementType.ROLE, note=""),
                AuthzPathElement(id="role_3", name="role_3", type=AuthzPathElementType.ROLE, note=""),
            ],
            permission=PermissionLevel.READ,
            asset=Asset(name="db1.schema1.table1", type=AssetType.TABLE),
        )
    )


def test_super_user_grant():
    """Test user with direct access to table"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(USER_ONE_SUPER, NO_ROLES_GRANTS, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[
                AuthzPathElement(id="super_user", name="super_user", type=AuthzPathElementType.ROLE, note=""),
            ],
            permission=PermissionLevel.FULL,
            asset=Asset(name="db1.schema1.table3", type=AssetType.TABLE),
        )
    )


def _call_analyzer(cursor: MagicMock, mocked_writer: MockWriter):
    analyzer = PostgresAuthzAnalyzer(cursors=[cursor], logger=MagicMock(), writer=mocked_writer.mocked_writer)
    analyzer.run()
