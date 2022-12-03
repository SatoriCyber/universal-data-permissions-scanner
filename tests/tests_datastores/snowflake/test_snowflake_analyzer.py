from unittest.mock import MagicMock
from authz_analyzer import SnowflakeAuthzAnalyzer
from authz_analyzer.models.model import AuthzEntry, AuthzPathElement, PermissionLevel
from authz_analyzer.writers.base_writers import OutputFormat
from tests.tests_datastores.snowflake.mocks.mock_connector import MockCursor
from tests.tests_datastores.snowflake.mocks import grants
from tests.mocks.mock_writers import MockWriter


def test_user_role_no_role_grants():
    """Test user with role, but role don't have permissions"""
    mocked_writer = MockWriter.get()
    with MockCursor(grants.SINGLE_USER_ROLE, grants.NO_ROLES_GRANTS) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_not_called()


def test_user_role_with_grant():
    """Test user with role and grant"""
    mocked_writer = MockWriter.get()
    with MockCursor(grants.SINGLE_USER_ROLE, grants.SINGLE_GRANT_ROLE) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity="user_1",
            path=[AuthzPathElement(id="role_1", name="role_1", type="role", note="")],
            permission=PermissionLevel.Read,
            asset="db1.schema1.table1",
        )
    )


def test_user_role_to_role_grant():
    """Test user with role1, role1 mapped to role2 which doesn't have grants"""
    mocked_writer = MockWriter.get()
    with MockCursor(grants.SINGLE_USER_ROLE, grants.ROLE_TO_ROLE_GRANT_NO_GRANTS) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_not_called()


def test_user_role_to_role_with_grant():
    """Test user with role1, role1 mapped to role2, role_2 has grant"""
    mocked_writer = MockWriter.get()
    with MockCursor(grants.SINGLE_USER_ROLE, grants.ROLE_TO_ROLE_GRANT_WITH_GRANTS) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity="user_1",
            path=[
                AuthzPathElement(id="role_1", name="role_1", type="role", note=""),
                AuthzPathElement(id="role_2", name="role_2", type="role", note=""),
            ],
            permission=PermissionLevel.Read,
            asset="db1.schema1.table1",
        )
    )


def _call_analyzer(cursor: MagicMock, mocked_writer: MockWriter):
    analyzer = SnowflakeAuthzAnalyzer(cursor=cursor, logger=MagicMock(), writer=mocked_writer.mocked_writer)
    analyzer.run()
