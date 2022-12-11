from unittest.mock import MagicMock
from authz_analyzer import SnowflakeAuthzAnalyzer
from authz_analyzer.datastores.snowflake.exporter import USER_TYPE, ASSET_TYPE
from authz_analyzer.models.model import AuthzEntry, AuthzPathElement, PermissionLevel, Identity, Asset
from tests.tests_datastores.snowflake.mocks.snowflake_mock_connector import SnowflakeMockCursor
from tests.tests_datastores.snowflake.mocks import grants
from tests.mocks.mock_writers import MockWriter


def test_user_role_no_role_grants():
    """Test user with role, but role don't have permissions"""
    mocked_writer = MockWriter.get()
    with SnowflakeMockCursor(grants.USER_ONE_ROLE_ONE, grants.NO_ROLES_GRANTS) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_not_called()


def test_user_role_with_grant():
    """Test user with role and grant"""
    mocked_writer = MockWriter.get()
    with SnowflakeMockCursor(grants.USER_ONE_ROLE_ONE, grants.ROLE_ONE_GRANT_TABLE_ONE) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(name="user_1", id="user_1@example.com", type=USER_TYPE),
            path=[AuthzPathElement(id="role_1", name="role_1", type="role", note="")],
            permission=PermissionLevel.Read,
            asset=Asset(name="db1.schema1.table1", type=ASSET_TYPE),
        )
    )


def test_user_role_to_role_grant():
    """Test user with role1, role1 mapped to role2 which doesn't have grants"""
    mocked_writer = MockWriter.get()
    with SnowflakeMockCursor(grants.USER_ONE_ROLE_ONE, grants.ROLE_TO_ROLE_GRANT_NO_GRANTS) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_not_called()


def test_user_role_to_role_with_grant():
    """Test user with role1, role1 mapped to role2, role_2 has grant"""
    mocked_writer = MockWriter.get()
    with SnowflakeMockCursor(grants.USER_ONE_ROLE_ONE, grants.ROLE_ONE_TABLE_ONE_THROUGH_ROLE_TWO) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(name="user_1", id="user_1@example.com", type=USER_TYPE),
            path=[
                AuthzPathElement(id="role_1", name="role_1", type="role", note=""),
                AuthzPathElement(id="role_2", name="role_2", type="role", note=""),
            ],
            permission=PermissionLevel.Read,
            asset=Asset(name="db1.schema1.table1", type=ASSET_TYPE),
        )
    )


def _call_analyzer(cursor: MagicMock, mocked_writer: MockWriter):
    analyzer = SnowflakeAuthzAnalyzer(cursor=cursor, logger=MagicMock(), writer=mocked_writer.mocked_writer)
    analyzer.run()
