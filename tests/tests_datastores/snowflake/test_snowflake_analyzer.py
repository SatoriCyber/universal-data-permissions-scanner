from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple
from unittest.mock import MagicMock, call
import hashlib
import pytest

from universal_data_permissions_scanner import SnowflakeAuthzAnalyzer
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

ShareName = str


class UserGrant(NamedTuple):
    name: str
    role: str
    email: str


class RoleGrant(NamedTuple):
    role: str
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
    id: str  # pylint: disable=invalid-name
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
    extra_path: Optional[List[AuthzPathElement]] = None,
):
    authz_path = [
        AuthzPathElement(
            id=share_path.id,
            name=share_path.name,
            type=AuthzPathElementType.SHARE,
            db_permissions=[],
        )
    ]
    if extra_path is not None:
        authz_path.extend(extra_path)
    authz_path[-1].db_permissions = share_path.db_permissions
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
            [RoleGrant("role_1", "SELECT", "db1", "schema1", "table1", "TABLE")],
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
                RoleGrant("role_1", "USAGE", "", "", "role_2", "ROLE"),
                RoleGrant("role_2", "SELECT", "db1", "schema1", "table1", "TABLE"),
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
            [RoleGrant("role_1", "USAGE", "", "", "role_2", "ROLE"), RoleGrant("role_2", "", "", "", "", "")],
            []
            # end test 4
        ),
        (  # test 5
            [UserGrant("user_1", "role_1", "user_1@example.com")],
            [
                RoleGrant("role_1", "REFERENCES", "db1", "schema1", "table1", "TABLE"),
                RoleGrant("role_1", "SELECT", "db1", "schema1", "table1", "TABLE"),
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
                    roles_path=[RolePath("role_1", ["REFERENCES", "SELECT"])],
                )
            ]
            # end test 5
        ),
    ],
    ids=(
        "User with no role",
        "user with one role access to one table",
        "user has role1, role1 has role2, role2 has permission on table",
        "user1 has role1, role1 has role2, role2 got no permissions",
        "user with one role multiple permissions",
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
    "share,grant_share,roles,expected_writes",
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
            [],
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
        (  # test 4
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
                "FUNCTION",
                "FUNC1",
                "SHARE",
                "PDA02239.SHARE1",
                "false",
                "ACCOUNTADMIN",
            ),
            [],
            [],
        ),
        (  # test 5
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
                "DATABASE_ROLE",
                "DB1.ROLE_SHARE",
                "SHARE",
                "PDA02239.SHARE1",
                "false",
                "ACCOUNTADMIN",
            ),
            [],
            [],
        ),
        (  # test 6
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
                "DATABASE_ROLE",
                "DB1.ROLE_SHARE",
                "SHARE",
                "PDA02239.SHARE1",
                "false",
                "ACCOUNTADMIN",
            ),
            [
                RoleGrant(
                    role="ROLE_SHARE",
                    permission="SELECT",
                    db="DB1",
                    schema="SCHEMA1",
                    table="TABLE1",
                    asset_type="TABLE",
                )
            ],
            [
                generate_authz_share(
                    "ACCOUNT1",
                    IdentityType.ACCOUNT,
                    "DB1",
                    "SCHEMA1",
                    "TABLE1",
                    PermissionLevel.READ,
                    SharePath("OUGNBIN.PDA02239.SHARE1", "SHARE1", ["SELECT"]),
                    [
                        AuthzPathElement(
                            id="ROLE_SHARE",
                            name="ROLE_SHARE",
                            type=AuthzPathElementType.ROLE,
                            notes=[],
                            db_permissions=["SELECT"],
                        )
                    ],
                )
            ],
        ),
    ],
    ids=(
        "Outbound share no account",
        "No relevant permissions",  # We grant usage permission on database, but no access to data
        "Outbound simple share",
        "Outbound simple share ignore for function",
        "Share with database user with no access",
        "Share with database user with access",
    ),
)
def test_snowflake_analyzer_shares(
    share: Share, grant_share: GrantsShare, roles: List[RoleGrant], expected_writes: List[AuthzEntry]
):
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
    snowflake_mock_service.role_grants = roles
    _call_analyzer(snowflake_mock_service.get(), mocked_writer)
    if len(expected_writes) != 0:
        mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore
    else:
        mocked_writer.assert_write_entry_not_called()


@pytest.mark.parametrize(
    "rsa_key, password, expected",
    [
        (
            """ 
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6TAbBgkqhkiG9w0BBQMwDgQI7+JBZKQNQVoCAggABIIEyI/ezj17Nor++B5/
b0t0e/aJlqrODaPhsPzHOLt8cWsL39frHfurSXyy7hsnYRyZbyU5YqgxNiRoMAwY
AxlFpgV/4u5vbTms5bZbcQ1GuBdTB/lKV8pmLDe9wKrxMspGnRwIcCOEUO3qEjyW
iT5q4UlbSWASIum+dNhN1XNufdlXdhnKNi97YckQy1qWJl7Mt/23uQtpD2ppqMDa
YMBBIqM7AkOdlZ81HqgM5wyl8H+bnFELYPBsriDL57FhxSEppS0fLyLJBUtYONzw
XPorP/UsZz65hw6UYVmArH17/3PrQ96liioP10LIJ7Y9YM0kYiFzW3I3qjMIADsU
vB3KCP2qDEuV1mQ7cNZlfocoUdGu++x7yzGjqz4Bi7/qd1+2TMH7OSMAXCPTxA3n
e3IoV3BsA438I7+BceAFA+7FbHdx/Z/vTJIfETq8KsicA6yMD+SU9jJYtEptDzqC
BuWCrvu2dsbjsOfHzowHz7XsmsLTryULVKPlCOlOVzUMK2yLd5Yg8x71AUYEkWWJ
6Q22VzUlZFrn8BUXh5gTIs6fJw2sydMw0IdaRRWzezg/EGw6LDplaxZnW0aSi1wN
3sosEo23QmPXT2KOXArxO0eXqBbw2oYy4Xc8OCFySxinAS7wZvGHVE1IGpqWqS1u
iUdSkY7Yn/+cF0j6Cb0p8eKOBuKo0QJ3+NU0GmO4ZD2tQfz0oqwvg7Nz9Sg4c+ri
AAPpHQT87l6GHu00h2uGC7Mg5aqqLBIRFBLg2B7WjVf/bgh67tFLLorb+nKkyyDz
FHZWwez01QdrM/Zy6HzDRpUV7ihhuSuYS+LmOL2aPy6zCxAP708XsHFhweuvLTU9
cUlfxky3QEk2mil30VZ93SVZ8D8do/Dy8oX8S+RR40OvGdZNQfvk+obr1tZPjvxk
gycfrd7joGuX+NvNq4ys8jFDhuLNozRwwQGOrchcDVL4unu32J40DmAGT6dNg0Lk
nRZEcW9zv88Rx+sXyaPgY9xQ/zTgi/Q61SrOYCV50+kvw3f5u7hc+pDD+7R0kwom
HTQ8TUCr0n8pZ2hX50LkbHVom6ulsfh+jyemXXzOeSp/FEzf1VcY5PDRpp+rG40k
k7fAoGOeAhCjAmsFRTJRE85tXXmJ7ZvlOwCYkddUIQVPhYPexvsoVAD6+P1/wvOT
D/WqhsSaHMskJK1X5Hll1aPmCMK+nss0kQfRDFj5S8PhUvFRpy7cbfvRKdi3A8BV
zK5buJB2akk37ZYIydLhW1FoKKOhEfutHNZDuxxf2/xoT8kjqrrii/fcAbhzEaKQ
3uQZMCknS+tcBNyRsmw3xoSalwyef0QPZyIRHsXYp8gPA7HhjIavqpa3Z3BY35n+
MPIvWVgGEsohFhVmTqzMaY86jSQE8vnvPOOBWWB1bhJQt7XYSIzVYQ9iclhzZuqN
99hUcsLFEdntnffGKir86xtnNg90h6VqT5POxsbZFgmWkmd5+0+pEyy/rdYtZwl5
bJcEwSrOVxewbVIweD8aiNfCK4SlB7TqibsgCXFiPL8xzKhMKKCSFjY2/2nlZLXA
MWfPy/lI6uwk9/IfTDqhj072f59Y6+wz8grvJtiOtSl83+427IsPpdTAdHmvvVfc
QL/fsRCErfq+UAiJbA==
-----END ENCRYPTED PRIVATE KEY-----
""",
            "test",
            "a8d46ae6de90037bc03f69d2dd41880ab4c41c2db900b18baae6d00c7be05811",
        ),
        (
            """ 
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCb3GChHX3l7Ba9
yfm+hTGcjJKSZImiBC/riR0wYdd6jIAyehDhLjDwlH7qpn2L9dLULxb5Z0PCDC1h
MkNnfVIWpJhEoGtDv/eVQlhtC6TfJGH6/u2hr/7NrjUuABrlOCaZMZbA4zhltc2q
buzDMd4hnw7CxrLzR6OMvAR90GZojXgoQmE1wN1GX4J1ol1ioHMEr2sPqHz/MfxM
HibgIU2hop3sxAn1KFf9phFGA3hm29kWhJdYJJnXk5ON4bS9enwJA6GFjtKDWXut
BWg99k+77L60LAWhvtgH8QkY5ZYOLVMqdaiVs0kQqifQtz1/dgStUF4r8OAmozj9
WnTL/2QzAgMBAAECggEAFW4Yry5x6BItEk1aFHMV3jOJ160RK4Ct4hHJPKTHTudQ
nSAhgASs3/da+AKKUpsrMNeErigfreekua+CixE1Hz3kXdM8zGTxsskbhWrLcY78
FdnFbKzZOQiR8VA8YnX1AK1L0But3nY/4AY+cZxCsZbAHdHaOw8HkssrRu1Hl2pd
PaNjyWesL2a1sbTa7lpWaSoyy813SIuVtH86jnGnmkNGvjAWHilvqQ4mHXl1FmoQ
X7LQoTnNXecbnMeIfNg+2xTxSDgwaF816XzQrmKiREMMZwi4INj22HpZo5FpX1Kr
j2RXlUj7SLBeYM4+3+s2V7Z6hI3zV//9RRZiAntY6QKBgQDN0XcmzjvmlpE+Hs2M
svmw0wcKiNHgENG2MigF5MTr/eCI2OoqLtJRcC3U4kmzYPBjoSn5yCvJXXJP3kOS
3RbMD0qHn/s37UCKQq2ykKm0RDQzyMcy+gTrRRqwYsEFvg9aYdng5Ac9iiDkGcY9
n1ytOIUF4+pzZ1LKgK9Q9M5JVQKBgQDB3LpP8dyXQaLE2lpLWnivSYhyFXnhmN3W
cuoGV8WNiPig+3O0PncK8TF2Ym5TapIzlUCyTOJh26WjmbWtKJ1Pkm5YR6l2JiyJ
pKzvHZ9RYMkHosZvHqzWMPKjqJ5NEx7FRmjXle2ZNtQQvhyA/i6yxGdHfYHeMFGP
cKk72cRXZwKBgQCoMfZyYvU2snMNVfTad2RvqXTGmhsRRg1rHD/y2QpIZNd6XfG2
+T5syQTbRPW/voeUk58O/hMyYshJFrUYLs8zgYeBoC6XfK5Sjr0OAQR+SYJzky+e
rA0bCwUNghaFj9VSIkcAbriwBNJuNdX4g+Qjtt2We7QcDSLuVA1xVi3CZQKBgA3e
zhHEO0UzNAMjoEw9596aw0FuWe8TMeQTCr1zcDYFM8zI0Ol3gqrswN44gq5DNLyu
FBftulDIF1zSNZZzDnZQAsccMXq7lnoupxTgqLJ420lJkysGJdWZYPLmsJTRJmV0
+TFbj8lji966y21LQmoV9VG/IBiWmm9J30Hh/dNHAoGAUU043I6oScB2MsYJVMDW
hZrSr2BX/Qe7r38dApkZinXhCpRstgGj6L+2Gn2Mpi8qBI14TAFkzcRcmOcwCK/I
s9F57ES837zGU2kYl8LbDPUkeU3QGxv78GBxc/geIb2aFvg7BbMiPfLQnFbqv1gz
OmaNtj0B9DQjsLqsxnrU1hM=
-----END PRIVATE KEY-----
""",
            None,
            "19e6134ff79b30b0b3a354ab98504127fb7f3fa043fc8f3caaa0b348193e5fd1",
        ),
    ],
)
def test_snowflake_analyzer_read_private_key(rsa_key, password, expected):
    rsa_key = SnowflakeAuthzAnalyzer._read_private_key(rsa_key, password)
    m = hashlib.sha256()
    m.update(rsa_key)
    m.digest()
    assert m.hexdigest() == expected
