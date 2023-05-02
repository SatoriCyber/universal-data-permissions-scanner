from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple, Union
from unittest.mock import MagicMock, call

import pytest
from redshift_connector import Cursor  # type: ignore

from universal_data_permissions_scanner import RedshiftAuthzAnalyzer
from universal_data_permissions_scanner.datastores.aws.analyzer.redshift.analyzer import ShareName
from universal_data_permissions_scanner.datastores.aws.analyzer.redshift.model import ShareObjectType, ShareType
from universal_data_permissions_scanner.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzNote,
    AuthzNoteType,
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


class SharesEntry(NamedTuple):
    """Defines a share entry, pg_catalog.svv_datashares"""

    share_id: str
    share_name: str
    source_database: str


class SharesConsumers(NamedTuple):
    """Share to which account, and cluster"""

    share_name: str
    consumer_account: str
    consumer_namespace: str


class DatashareDesc(NamedTuple):
    """Defines a datashare objects access"""

    producer_account: str
    producer_namespace: str
    share_type: str  # OUTBOUND/INBOUND
    share_name: str
    object_type: str  # SCHEMA/TABLE etc'
    object_name: str  # OBJECT_NAME, SCHEMA.TABLE


def create_datashare_desc(
    share_type: ShareType, share_name: str, object_type: ShareObjectType, object_name: str
) -> DatashareDesc:
    return DatashareDesc(
        producer_account="",
        producer_namespace="",
        share_type=share_type.value,
        share_name=share_name,
        object_type=object_type.value,
        object_name=object_name,
    )


@dataclass
class RedshiftMockService:
    mocked_service: MagicMock
    cursors: Dict[str, MagicMock] = field(default_factory=dict)
    identities: Dict[MagicMock, List[IdentityDB]] = field(default_factory=dict)
    identities_privileges: Dict[MagicMock, List[IdentitiesPrivileges]] = field(default_factory=dict)
    all_tables: Dict[MagicMock, List[Table]] = field(default_factory=dict)
    datashares: List[SharesEntry] = field(default_factory=list)
    datashare_consumers: List[SharesConsumers] = field(default_factory=list)
    datashare_desc: Dict[ShareName, List[DatashareDesc]] = field(default_factory=dict)

    @classmethod
    def new(cls):
        mocked_service = MagicMock(name="RedshiftMockService")
        instance = cls(mocked_service)
        mocked_get_rows = MagicMock(name="RedshiftServiceGetRows", side_effect=instance._get_rows)

        mocked_service.get_rows = mocked_get_rows
        return instance

    def add_database(
        self,
        database_name: str,
        identities: List[IdentityDB],
        identities_privileges: List[IdentitiesPrivileges],
        all_tables: List[Table],
    ) -> None:
        """Add a database to the mocked service along with its identities and privileges.

        Args:
            database_name (str): Name of the database
            identities (List[IdentityDB]): Identities to roles
            identities_privileges (List[str]): Identities privileges
        """
        mocked_cursor = MagicMock(name=f"RedshiftServiceCursor{database_name}", spec=Cursor)  # type: ignore
        mocked_connection = MagicMock(name=f"RedshiftServiceConnection{database_name}")  # type: ignore
        mocked_cursor.connection = mocked_connection
        self.cursors[database_name] = mocked_cursor
        self.identities[mocked_cursor] = identities
        self.identities_privileges[mocked_cursor] = identities_privileges
        self.all_tables[mocked_cursor] = all_tables

    def add_datashare(
        self,
        share_id: str,
        share_name: str,
        consumer_namespace: str,
        source_database: str,
        objects: List[DatashareDesc],
        consumer_account: Optional[str] = None,
    ):
        self.datashares = [SharesEntry(share_id=share_id, share_name=share_name, source_database=source_database)]
        if consumer_account is None:
            consumer_account = ""
        self.datashare_consumers = [
            SharesConsumers(
                share_name=share_name, consumer_account=consumer_account, consumer_namespace=consumer_namespace
            )
        ]
        self.datashare_desc[share_name] = objects

        mocked_cursor = MagicMock(name=f"RedshiftServiceCursor{source_database}", spec=Cursor)  # type: ignore
        mocked_connection = MagicMock(name=f"RedshiftServiceConnection{source_database}")  # type: ignore
        mocked_cursor.connection = mocked_connection
        self.cursors[source_database] = mocked_cursor
        self.identities[mocked_cursor] = []
        self.identities_privileges[mocked_cursor] = []
        self.all_tables[mocked_cursor] = []

    def get(self):
        self.mocked_service.cursors = self.cursors
        return self.mocked_service

    def _get_rows(
        self, redshift_cursor: MagicMock, command_name: Path, params: Optional[str] = None
    ) -> Sequence[Tuple[Union[str, bool], ...]]:
        identities = self.identities[redshift_cursor]
        identities_privileges = self.identities_privileges[redshift_cursor]
        if command_name == Path("identities.sql"):
            return identities
        if command_name == Path("identities_privileges.sql"):
            return identities_privileges
        if command_name == Path("all_tables.sql"):
            return self.all_tables[redshift_cursor]
        if command_name == Path("datashares.sql"):
            return self.datashares
        if command_name == Path("datashare_consumers.sql"):
            return self.datashare_consumers
        if command_name == Path("datashare_desc.sql") and params is not None:
            try:
                return self.datashare_desc[params]
            except KeyError as err:
                raise Exception(
                    f"share {params} wasn't found among mocked shares, mocked_shares: {self.datashare_desc}"
                ) from err
        if command_name == Path("datashare_desc.sql"):
            raise Exception("datashare_desc.sql requires share name")
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
        (
            "db1",
            [IdentityDB("user_id_1", "user_1", "USER", "", "", "", False)],
            [],
            [],
            [],
        ),  # test 2 - user with no role
        (  # test 3 - user with direct access
            "db1",
            [IdentityDB("user_id_1", "user_1", "USER", "", "", "", False)],
            [IdentitiesPrivileges("UNKNOWN", "user_id_1", "schema_1", "table_1", "SELECT")],
            [],
            [
                generate_authz_entry(
                    ["db1", "schema_1", "table_1"],
                    [
                        AuthzPathElement(
                            "user_id_1",
                            "user_1",
                            AuthzPathElementType.USER,
                            [AuthzNote("", AuthzNoteType.GENERIC)],
                            ["SELECT"],
                        )
                    ],
                    "user_id_1",
                    "user_1",
                    PermissionLevel.READ,
                )
            ],
        ),
        (  # test 4 - user with role and privs
            "db1",
            [IdentityDB("user_id_1", "user_1", "USER", "ROLE_1_ID", "ROLE_1", "ROLE", False)],
            [IdentitiesPrivileges("UNKNOWN", "ROLE_1_ID", "schema_1", "table_1", "SELECT")],
            [],
            [
                generate_authz_entry(
                    ["db1", "schema_1", "table_1"],
                    [
                        AuthzPathElement(
                            "ROLE_1_ID",
                            "ROLE_1",
                            AuthzPathElementType.ROLE,
                            [AuthzNote("", AuthzNoteType.GENERIC)],
                            ["SELECT"],
                        )
                    ],
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
    mocked_writer = MockWriter.new()
    mock_service = RedshiftMockService.new()
    mock_service.add_database(database_name, identities, identities_privileges, all_tables)
    _call_analyzer(mock_service, mocked_writer)
    if len(expected_writes) != 0:
        mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore
    else:
        mocked_writer.assert_write_entry_not_called()


def test_datashare():
    share_name = "share_1"
    share_id = "share_id_1"
    consumer_namespace = "consumer_namespace_1"
    database = "db1"
    share_type = ShareType.OUTBOUND
    object_type = ShareObjectType.TABLE
    object_name = "schema_1.table_1"
    asset_name = [database]
    asset_name.extend(object_name.split("."))
    expected_writes = [
        call(
            AuthzEntry(
                identity=Identity(
                    id=consumer_namespace,
                    name=consumer_namespace,
                    type=IdentityType.CLUSTER,
                ),
                asset=Asset(
                    name=asset_name,
                    type=AssetType.TABLE,
                ),
                path=[
                    AuthzPathElement(
                        id=share_id,
                        name=share_name,
                        type=AuthzPathElementType.SHARE,
                        notes=[
                            AuthzNote(
                                note="share share_1 grants access to account None in the following namespace consumer_namespace_1",
                                type=AuthzNoteType.GENERIC,
                            )
                        ],
                        db_permissions=[],
                    )
                ],
                permission=PermissionLevel.READ,
            )
        )
    ]
    objects = create_datashare_desc(share_type, share_name, object_type, object_name)

    mocked_writer = MockWriter.new()
    mock_service = RedshiftMockService.new()
    mock_service.add_datashare(share_id, share_name, consumer_namespace, database, [objects])

    _call_analyzer(mock_service, mocked_writer)
    if len(expected_writes) != 0:
        mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore
    else:
        mocked_writer.assert_write_entry_not_called()


def _call_analyzer(service: RedshiftMockService, mocked_writer: MockWriter):
    analyzer = RedshiftAuthzAnalyzer(service=service.get(), cursors=service.cursors, logger=MagicMock(), writer=mocked_writer.get())  # type: ignore
    analyzer.run()
