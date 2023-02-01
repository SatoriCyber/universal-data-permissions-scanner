from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple
from unittest.mock import MagicMock, call

import pytest

from authz_analyzer import SnowflakeAuthzAnalyzer
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

ShareName = str


class UserGrant(NamedTuple):
    name: str
    role: str
    email: str


class RoleGrant(NamedTuple):
    role: str
    grant: str
    permission: str
    db: str
    schema: str
    table: str
    asset_type: str


class Share(NamedTuple):
    """Results for the show shares command."""

    created_on: str
    kind: str
    name: str
    database_name: str
    to: str
    owner: str
    comment: str
    listing_global_name: str


class GrantsShare(NamedTuple):
    """Results of show grants to share <share name>."""

    created_on: str
    privilege: str
    granted_on: str
    name: str
    granted_to: str
    grantee_name: str
    grant_option: str
    granted_by: str


@dataclass
class SnowflakeMockService:
    mocked_service: MagicMock
    user_grants: List[UserGrant] = field(default_factory=list)
    role_grants: List[RoleGrant] = field(default_factory=list)
    shares: List[Share] = field(default_factory=list)
    grants_share: Dict[ShareName, List[GrantsShare]] = field(default_factory=dict)

    @classmethod
    def new(cls):
        mocked_service = MagicMock(name="SnowflakeMockService")  # type: ignore
        instance = cls(mocked_service)
        mocked_get_rows = MagicMock(name="SnowflakeServiceGetRows", side_effect=instance._side_effect_execute)

        mocked_service.get_rows = mocked_get_rows
        return instance

    def add_user(self, user_grant: UserGrant) -> None:
        self.user_grants.append(user_grant)

    def add_role_grant(self, role_grant: RoleGrant) -> None:
        self.role_grants.append(role_grant)

    def add_grant_share(self, grant_share: GrantsShare):
        self.grants_share.setdefault(grant_share.grantee_name.split(".")[-1], []).append(grant_share)

    def get(self):
        return self.mocked_service

    def _side_effect_execute(self, file_name_command: Path, params: Optional[str] = None) -> Sequence[Tuple[str, ...]]:
        if file_name_command == Path("user_grants.sql"):
            return self.user_grants
        if file_name_command == Path("grants_roles.sql"):
            return self.role_grants
        if file_name_command == Path("shares.sql"):
            return self.shares
        if file_name_command == Path("grants_to_share.sql"):
            if params is None:
                raise Exception("Params is None")
            return self.grants_share[params]
        raise Exception(f"Command {file_name_command} not mocked")


class RolePath(NamedTuple):
    name: str
    db_permissions: List[str]


class SharePath(NamedTuple):
    id: str
    name: str
    db_permissions: List[str]


def generate_authz_entry(
    identity_name: str,
    identity_id: str,
    identity_type: IdentityType,
    db: str,
    schema: str,
    table: str,
    permission: PermissionLevel,
    path: List[AuthzPathElement],
):
    return call(
        AuthzEntry(
            asset=Asset(name=[db, schema, table], type=AssetType.TABLE),
            path=path,
            identity=Identity(id=identity_id, type=identity_type, name=identity_name),
            permission=permission,
        )
    )


def generate_authz_entry_role(
    username: str,
    user_id: str,
    identity_type: IdentityType,
    db: str,
    schema: str,
    table: str,
    permission: PermissionLevel,
    roles_path: List[RolePath],
):
    authz_path = [
        AuthzPathElement(
            id=role_path.name,
            name=role_path.name,
            type=AuthzPathElementType.ROLE,
            db_permissions=role_path.db_permissions,
        )
        for role_path in roles_path
    ]
    return generate_authz_entry(username, user_id, identity_type, db, schema, table, permission, authz_path)


def generate_authz_share(
    account: str,
    identity_type: IdentityType,
    db: str,
    schema: str,
    table: str,
    permission: PermissionLevel,
    share_path: SharePath,
):
    authz_path = [
        AuthzPathElement(
            id=share_path.id,
            name=share_path.name,
            type=AuthzPathElementType.SHARE,
            db_permissions=share_path.db_permissions,
        )
    ]
    return generate_authz_entry(account, account, identity_type, db, schema, table, permission, authz_path)


@pytest.mark.parametrize(
    "users,roles,expected_writes",
    [
        (
            [("user_1", "role_1", "user_1@example.com")],
            [("", "", "", "", "", "", "")],
            [],
        ),  # test1
        (  # test 2
            [UserGrant("user_1", "role_1", "user_1@example.com")],
            [RoleGrant("", "role_1", "SELECT", "db1", "schema1", "table1", "TABLE")],
            [
                generate_authz_entry_role(
                    "user_1",
                    "user_1@example.com",
                    IdentityType.USER,
                    "db1",
                    "schema1",
                    "table1",
                    PermissionLevel.READ,
                    roles_path=[RolePath("role_1", ["SELECT"])],
                )
            ]
            # end test 2
        ),
        (  # test 3
            [UserGrant("user_1", "role_1", "user_1@example.com")],
            [
                RoleGrant("role_2", "role_1", "USAGE", "", "", "", "ROLE"),
                RoleGrant("", "role_2", "SELECT", "db1", "schema1", "table1", "TABLE"),
            ],
            [
                generate_authz_entry_role(
                    "user_1",
                    "user_1@example.com",
                    IdentityType.USER,
                    "db1",
                    "schema1",
                    "table1",
                    PermissionLevel.READ,
                    roles_path=[RolePath("role_1", []), RolePath("role_2", ["SELECT"])],
                )
            ]
            # end test 3
        ),
        (  # test 4
            [UserGrant("user_1", "role_1", "user_1@example.com")],
            [RoleGrant("role_2", "role_1", "USAGE", "", "", "", "ROLE"), RoleGrant("", "role_2", "", "", "", "", "")],
            []
            # end test 4
        ),
    ],
    ids=(
        "User with no role",
        "user with one role access to one table",
        "user has role1, role1 has role2, role2 has permission on table",
        "user1 has role1, role1 has role2, role2 got no permissions",
    ),
)
def test_snowflake_analyzer_user_role(
    users: List[UserGrant], roles: List[RoleGrant], expected_writes: List[AuthzEntry]
):
    """Test snowflake analyzer"""
    analyzer_mock = SnowflakeMockService.new()
    analyzer_mock.user_grants = users
    analyzer_mock.role_grants = roles

    mocked_writer = MockWriter.new()
    _call_analyzer(analyzer_mock.get(), mocked_writer)
    if len(expected_writes) != 0:
        mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore
    else:
        mocked_writer.assert_write_entry_not_called()


def _call_analyzer(service: MagicMock, mocked_writer: MockWriter):
    analyzer = SnowflakeAuthzAnalyzer(service=service, logger=MagicMock(), writer=mocked_writer.get())
    analyzer.run()


@pytest.mark.parametrize(
    "share,grant_share,expected_writes",
    [
        (  # test 1
            Share(
                "2023-01-22T05:03:45.169-08:00",
                "OUTBOUND",
                "OUGNBIN.PDA02239.SHARE1",
                "DB1",
                "",
                "ACCOUNTADMIN",
                "",
                "",
            ),
            GrantsShare(
                "2023-01-22 05:03:55.849 -0800",
                "SELECT",
                "TABLE",
                "DB1.SCHEMA1.CUSTOMERS",
                "SHARE",
                "PDA02239.SHARE1",
                "false",
                "ACCOUNTADMIN",
            ),
            [],
        ),
        (  # test 2
            Share(
                "2023-01-22T05:03:45.169-08:00",
                "OUTBOUND",
                "OUGNBIN.PDA02239.SHARE1",
                "DB1",
                "ACCOUNT1",
                "ACCOUNTADMIN",
                "",
                "",
            ),
            GrantsShare(
                "2023-01-22 05:03:55.849 -0800",
                "USAGE",
                "DATABASE",
                "DB1.SCHEMA1.CUSTOMERS",
                "SHARE",
                "PDA02239.SHARE1",
                "false",
                "ACCOUNTADMIN",
            ),
            [],
        ),
        (  # test 3
            Share(
                "2023-01-22T05:03:45.169-08:00",
                "OUTBOUND",
                "OUGNBIN.PDA02239.SHARE1",
                "DB1",
                "ACCOUNT1",
                "ACCOUNTADMIN",
                "",
                "",
            ),
            GrantsShare(
                "2023-01-22 05:03:55.849 -0800",
                "SELECT",
                "TABLE",
                "DB1.SCHEMA1.CUSTOMERS",
                "SHARE",
                "PDA02239.SHARE1",
                "false",
                "ACCOUNTADMIN",
            ),
            [
                generate_authz_share(
                    "ACCOUNT1",
                    IdentityType.ACCOUNT,
                    "DB1",
                    "SCHEMA1",
                    "CUSTOMERS",
                    PermissionLevel.READ,
                    SharePath("OUGNBIN.PDA02239.SHARE1", "SHARE1", ["SELECT"]),
                )
            ],
        ),
    ],
    ids=(
        "Outbound share no account",
        "No relevant permissions",  # We grant usage permission on database, but no access to data
        "Outbound simple share",
    ),
)
def test_snowflake_analyzer_shares(share: Share, grant_share: GrantsShare, expected_writes: List[AuthzEntry]):
    """Test the snowflake shares.

    There are two types of share:
    - Share which have direct access to a resource (e.g. table, view etc')
    - Share which have access to database user, and the database user has access to the resource
    for now, only the first is supported
    """
    snowflake_mock_service = SnowflakeMockService.new()
    mocked_writer = MockWriter.new()
    snowflake_mock_service.shares = [share]
    snowflake_mock_service.add_grant_share(grant_share)
    _call_analyzer(snowflake_mock_service.get(), mocked_writer)
    if len(expected_writes) != 0:
        mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore
    else:
        mocked_writer.assert_write_entry_not_called()
