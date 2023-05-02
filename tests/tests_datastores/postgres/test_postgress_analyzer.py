from typing import List, Optional
from unittest.mock import MagicMock

import pytest

from universal_data_permissions_scanner import PostgresAuthzAnalyzer
from universal_data_permissions_scanner.datastores.postgres.deployment import Deployment
from universal_data_permissions_scanner.datastores.postgres.model import RESOURCE_TYPE_MAP
from universal_data_permissions_scanner.models.model import (
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
from tests.tests_datastores.postgres.mocks.postgres_mock_connector import PostgresMockCursor, Role, RoleGrant, Table

ALL_TABLES = [
    Table(
        "db1",
        "schema1",
        "table3",
    )
]
USER_ONE_ROLE_ONE: List[Role] = [Role("user_1", False, "role_1", True)]
USER_ONE_DIRECT_ACCESS = [RoleGrant("table1", "schema1", "r", "user_1", None)]
NO_ROLES_GRANTS = [RoleGrant("", "", "", "", None)]
ROLE_ONE_GRANT_TABLE_ONE = [RoleGrant("table1", "schema1", "r", "role_1", None)]
ROLE_TWO_GRANT_TABLE_ONE = [RoleGrant("table1", "schema1", "r", "role_2", None)]
USER_ONE_ROLE_ONE_ROLE_2: List[Role] = [
    Role("user_1", False, "role_1", True),
    Role("role_1", False, "role_2", False),
]

THREE_ROLES_GRANTS: List[Role] = [
    Role("user_1", False, "role_1", True),
    Role("role_1", False, "role_2", False),
    Role("role_2", False, "role_3", False),
]
ROLE_THREE_GRANT_TABLE_ONE = [RoleGrant("table1", "schema1", "r", "role_3", None)]

USER_ONE_SUPER: List[Role] = [Role("user_1", True, None, True)]
USER_ONE_RDS_SUPER: List[Role] = [Role("user_1", False, "rds_superuser", True)]
USER_ONE_GCP_SUPER: List[Role] = [Role("user_1", False, "cloudsqlsuperuser", True)]


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
            path=[
                AuthzPathElement(
                    id="role_1", name="role_1", type=AuthzPathElementType.ROLE, db_permissions=["OWNERSHIP"]
                )
            ],
            permission=PermissionLevel.FULL,
            asset=Asset(name=["db1", "schema1", "table1"], type=AssetType.TABLE),
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
                AuthzPathElement(id="role_1", name="role_1", type=AuthzPathElementType.ROLE),
                AuthzPathElement(
                    id="role_2", name="role_2", type=AuthzPathElementType.ROLE, db_permissions=["OWNERSHIP"]
                ),
            ],
            permission=PermissionLevel.FULL,
            asset=Asset(name=["db1", "schema1", "table1"], type=AssetType.TABLE),
        )
    )


def test_user_role_with_direct_grant():
    """Test user with role1, role1 mapped to role2, role_2 maps to role_3, role_3 has grant"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(THREE_ROLES_GRANTS, ROLE_THREE_GRANT_TABLE_ONE, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[
                AuthzPathElement(id="role_1", name="role_1", type=AuthzPathElementType.ROLE),
                AuthzPathElement(id="role_2", name="role_2", type=AuthzPathElementType.ROLE),
                AuthzPathElement(
                    id="role_3", name="role_3", type=AuthzPathElementType.ROLE, db_permissions=["OWNERSHIP"]
                ),
            ],
            permission=PermissionLevel.FULL,
            asset=Asset(name=["db1", "schema1", "table1"], type=AssetType.TABLE),
        )
    )


def test_super_user_grant():
    """Test user with super access role"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(USER_ONE_SUPER, NO_ROLES_GRANTS, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer)
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[
                AuthzPathElement(
                    id="super_user",
                    name="super_user",
                    type=AuthzPathElementType.ROLE,
                    db_permissions=["super_user"],
                ),
            ],
            permission=PermissionLevel.FULL,
            asset=Asset(name=["db1", "schema1", "table3"], type=AssetType.TABLE),
        )
    )


def test_rds_super_user():
    """Test user with super access role"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(USER_ONE_RDS_SUPER, NO_ROLES_GRANTS, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer, Deployment.aws_rds())
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[
                AuthzPathElement(
                    id="rds_superuser",
                    name="rds_superuser",
                    type=AuthzPathElementType.ROLE,
                    db_permissions=["super_user"],
                ),
            ],
            permission=PermissionLevel.FULL,
            asset=Asset(name=["db1", "schema1", "table3"], type=AssetType.TABLE),
        )
    )


def test_gcp_super_user():
    """Test user with super access role"""
    mocked_writer = MockWriter.new()
    with PostgresMockCursor(USER_ONE_GCP_SUPER, NO_ROLES_GRANTS, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer, Deployment.gcp())
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[
                AuthzPathElement(
                    id="cloudsqlsuperuser",
                    name="cloudsqlsuperuser",
                    type=AuthzPathElementType.ROLE,
                    db_permissions=["super_user"],
                ),
            ],
            permission=PermissionLevel.FULL,
            asset=Asset(name=["db1", "schema1", "table3"], type=AssetType.TABLE),
        )
    )


@pytest.mark.parametrize(
    "relacl,permission,db_permissions",
    [
        ["{user_1=r/postgres}", PermissionLevel.READ, ["SELECT"]],
        ["{user_1=w/postgres}", PermissionLevel.WRITE, ["UPDATE"]],
        ["{user_1=a/postgres}", PermissionLevel.WRITE, ["INSERT"]],
        ["{user_1=d/postgres}", PermissionLevel.WRITE, ["DELETE"]],
        ["{user_1=D/postgres}", PermissionLevel.WRITE, ["TRUNCATE"]],
        ["{user_1=x/postgres}", PermissionLevel.READ, ["REFERENCES"]],
        ["{user_1=rw/postgres}", PermissionLevel.WRITE, ["SELECT", "UPDATE"]],
        ["{user_1=rt/postgres}", PermissionLevel.READ, ["SELECT"]],
    ],
    ids=(
        "user with select",
        "user with insert",
        "user with update",
        "user with delete",
        "user with truncate",
        "user with references",
        "user with two permissions",
        "user with one permission not relevant",
    ),
)
def test_relacl_single_user(relacl: str, permission: PermissionLevel, db_permissions: List[str]):
    """The relacl column is a comma separated list of grants. for example:
    {postgres=arwdDxt/postgres,data_access_west=r/postgres,data_access_east=r/postgres}
    where the first element is the grantee second is the list of permissions defined here:
    https://www.postgresql.org/docs/current/ddl-priv.html#:~:text=Table%C2%A05.1.%C2%A0ACL%20Privilege%20Abbreviations
    And the third is the grantor.
    """
    role_grant: list[RoleGrant] = [RoleGrant("table1", "schema1", "r", "postgres", relacl)]
    mocked_writer = MockWriter.new()
    with PostgresMockCursor([Role("user_1", False, None, True)], role_grant, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer, Deployment.aws_rds())
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[
                AuthzPathElement(
                    id="user_1",
                    name="user_1",
                    type=AuthzPathElementType.ROLE,
                    db_permissions=db_permissions,
                ),
            ],
            permission=permission,
            asset=Asset(name=["db1", "schema1", "table1"], type=AssetType.TABLE),
        )
    )


def get_resource_type_as_tuples():
    return list(RESOURCE_TYPE_MAP.items())


@pytest.mark.parametrize(
    "resource_type_db_letter,resource_type",
    get_resource_type_as_tuples(),
    ids=[str(resource_type) for resource_type in RESOURCE_TYPE_MAP.values()],
)
def test_relacl_resource_type(resource_type_db_letter: str, resource_type: AssetType):
    """Postgres as different kind of resources, for example tables, toast tables, sequences, etc.
    https://www.postgresql.org/docs/current/catalog-pg-class.html#:~:text=temporary%20table/sequence-,relkind%20char,-r%20%3D%20ordinary%20table
    """
    role_grant: list[RoleGrant] = [
        RoleGrant("table1", "schema1", resource_type_db_letter, "postgres", "{user_1=r/postgres}")
    ]
    mocked_writer = MockWriter.new()
    with PostgresMockCursor([Role("user_1", False, None, True)], role_grant, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer, Deployment.aws_rds())
    mocked_writer.assert_write_entry_called_once_with(
        AuthzEntry(
            identity=Identity(id="user_1", type=IdentityType.ROLE_LOGIN, name="user_1"),
            path=[
                AuthzPathElement(
                    id="user_1",
                    name="user_1",
                    type=AuthzPathElementType.ROLE,
                    db_permissions=["SELECT"],
                ),
            ],
            permission=PermissionLevel.READ,
            asset=Asset(name=["db1", "schema1", "table1"], type=resource_type),
        )
    )


def test_relacl_not_relevant_resource_type():
    """Sequence is not relevant for us, so we should not get any entry for it."""
    role_grant: list[RoleGrant] = [RoleGrant("table1", "schema1", "s", "postgres", "{user_1=r/postgres}")]
    mocked_writer = MockWriter.new()
    with PostgresMockCursor([Role("user_1", False, None, True)], role_grant, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer, Deployment.aws_rds())
    mocked_writer.assert_write_entry_not_called()


def test_relacl_not_relevant():
    role_grant: list[RoleGrant] = [RoleGrant("table1", "schema1", "t", "postgres", "{user_1=t/postgres}")]
    mocked_writer = MockWriter.new()
    with PostgresMockCursor([Role("user_1", False, None, True)], role_grant, ALL_TABLES) as mocked_connector:
        _call_analyzer(mocked_connector, mocked_writer, Deployment.aws_rds())
    mocked_writer.assert_write_entry_not_called()


def _call_analyzer(
    cursor: MagicMock, mocked_writer: MockWriter, deployment: Optional[Deployment] = None, db_name: str = "db1"
):
    if deployment is None:
        deployment = Deployment.other()
    analyzer = PostgresAuthzAnalyzer(
        cursors={db_name: cursor}, logger=MagicMock(), writer=mocked_writer.mocked_writer, deployment=deployment
    )
    analyzer.run()
