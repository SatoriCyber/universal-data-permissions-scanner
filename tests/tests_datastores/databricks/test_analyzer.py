from __future__ import annotations

from typing import List
from unittest.mock import _Call  # type: ignore

import pytest

from universal_data_permissions_scanner.datastores.databricks.model import DBPermissionLevel
from universal_data_permissions_scanner.datastores.databricks.policy_tree import DB_PERMISSION_PERMISSION_MAP
from universal_data_permissions_scanner.datastores.databricks.service.model import (
    Group,
    GroupMeta,
    ParsedUser,
    Ref,
    ResourceType,
    ServicePrincipal,
)
from universal_data_permissions_scanner.models.model import PermissionLevel
from tests.mocks.mock_writers import MockWriter
from tests.tests_datastores.databricks.generate_authz_entry import (
    build_catalog_service_principal_access,
    build_catalog_user_access,
    build_catalog_user_group_in_groups,
    build_direct_access_service_principal,
    build_direct_access_user,
    build_schema_service_principal_access,
    build_schema_user_access,
    build_schema_user_group_in_groups,
    build_service_principal_catalog_group_access,
    build_service_principal_member_of_group_direct_access,
    build_service_principal_schema_group_access,
    build_user_catalog_group_access,
    build_user_group_in_groups,
    build_user_member_of_group_direct_access,
    build_user_schema_group_access,
)
from tests.tests_datastores.databricks.mocks import DatabricksMock, TestTable


def test_owners_user():
    mock_databricks = DatabricksMock.new()
    catalog_name = "catalog1"
    schema_name = "schema1"
    table_name = "table1"

    user = ParsedUser(active=True, userName="user", id="12345")
    table = TestTable.new_identity_owner_all(user["userName"], table_name, schema_name, catalog_name)

    mock_databricks.add_user(user)
    mock_databricks.add_table(table)

    writer = MockWriter.new()
    mock_databricks.get(writer.get()).run()

    calls = build_ownership_calls_user(user, table)
    writer.mocked_writer.write_entry.assert_has_calls(calls)  # type: ignore


def test_owners_service_principal():
    mock_databricks = DatabricksMock.new()
    catalog_name = "catalog1"
    schema_name = "schema1"
    table_name = "table1"

    service_principal = ServicePrincipal(active=True, displayName="sa1", applicationId="12345", id="6789")
    table = TestTable.new_identity_owner_all(service_principal["applicationId"], table_name, schema_name, catalog_name)

    mock_databricks.add_service_principal(service_principal)
    mock_databricks.add_table(table)

    writer = MockWriter.new()
    mock_databricks.get(writer.get()).run()

    calls = [
        build_direct_access_service_principal(
            service_principal,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_schema_service_principal_access(
            service_principal,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_catalog_service_principal_access(
            service_principal,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
    ]
    writer.mocked_writer.write_entry.assert_has_calls(calls)  # type: ignore


def test_owners_groups_user():
    mock_databricks = DatabricksMock.new()
    catalog_name = "catalog1"
    schema_name = "schema1"
    table_name = "table1"

    user = ParsedUser(active=True, userName="user", id="12345")
    group = Group(
        displayName="Group1",
        id="6789",
        meta=GroupMeta(resourceType=ResourceType.GROUP),
        members=[Ref(ref=user["id"])],
        groups=[],
    )
    table = TestTable.new_identity_owner_all(group["displayName"], table_name, schema_name, catalog_name)

    mock_databricks.add_user(user)
    mock_databricks.add_table(table)
    mock_databricks.add_group(group)

    writer = MockWriter.new()
    mock_databricks.get(writer.get()).run()

    calls = [
        build_user_member_of_group_direct_access(
            user,
            group,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_user_schema_group_access(
            user,
            group,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_user_catalog_group_access(
            user,
            group,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
    ]
    writer.mocked_writer.write_entry.assert_has_calls(calls)  # type: ignore


def test_owners_groups_service_principal():
    mock_databricks = DatabricksMock.new()
    catalog_name = "catalog1"
    schema_name = "schema1"
    table_name = "table1"

    service_principal = ServicePrincipal(active=True, displayName="sa1", applicationId="12345", id="6789")
    group = Group(
        displayName="Group1",
        id="6789",
        meta=GroupMeta(resourceType=ResourceType.GROUP),
        members=[Ref(ref="ServicePrincipals/" + service_principal["id"])],
        groups=[],
    )
    table = TestTable.new_identity_owner_all(group["displayName"], table_name, schema_name, catalog_name)

    mock_databricks.add_service_principal(service_principal)
    mock_databricks.add_table(table)
    mock_databricks.add_group(group)

    writer = MockWriter.new()
    mock_databricks.get(writer.get()).run()

    calls = [
        build_service_principal_member_of_group_direct_access(
            service_principal,
            group,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_service_principal_schema_group_access(
            service_principal,
            group,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_service_principal_catalog_group_access(
            service_principal,
            group,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
    ]
    writer.mocked_writer.write_entry.assert_has_calls(calls)  # type: ignore


def test_owners_group_in_group():
    mock_databricks = DatabricksMock.new()
    catalog_name = "catalog1"
    schema_name = "schema1"
    table_name = "table1"

    user = ParsedUser(active=True, userName="user", id="12345")
    group1 = Group(
        displayName="Group1",
        id="6789",
        meta=GroupMeta(resourceType=ResourceType.GROUP),
        members=[Ref(ref=user["id"])],
        groups=[],
    )
    group2 = Group(
        displayName="Group2",
        id="101112",
        meta=GroupMeta(resourceType=ResourceType.GROUP),
        members=[Ref(ref="Groups/" + group1["id"])],
        groups=[],
    )
    groups = [group1, group2]
    table = TestTable.new_identity_owner_all(group2["displayName"], table_name, schema_name, catalog_name)

    mock_databricks.add_user(user)
    mock_databricks.add_table(table)
    mock_databricks.add_group(group1)
    mock_databricks.add_group(group2)

    writer = MockWriter.new()
    mock_databricks.get(writer.get()).run()

    calls = [
        build_user_group_in_groups(
            user,
            groups,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_schema_user_group_in_groups(
            user,
            groups,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_catalog_user_group_in_groups(
            user,
            groups,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
    ]
    writer.mocked_writer.write_entry.assert_has_calls(calls)  # type: ignore


def test_owners_three_groups():
    mock_databricks = DatabricksMock.new()
    catalog_name = "catalog1"
    schema_name = "schema1"
    table_name = "table1"

    user = ParsedUser(active=True, userName="user", id="12345")
    group1 = Group(
        displayName="Group1",
        id="6789",
        meta=GroupMeta(resourceType=ResourceType.GROUP),
        members=[Ref(ref=user["id"])],
        groups=[],
    )
    group2 = Group(
        displayName="Group2",
        id="101112",
        meta=GroupMeta(resourceType=ResourceType.GROUP),
        members=[Ref(ref="Groups/" + group1["id"])],
        groups=[],
    )
    group3 = Group(
        displayName="Group3",
        id="111213",
        meta=GroupMeta(resourceType=ResourceType.GROUP),
        members=[Ref(ref="Groups/" + group2["id"])],
        groups=[],
    )
    groups = [group1, group2, group3]
    table = TestTable.new_identity_owner_all(group3["displayName"], table_name, schema_name, catalog_name)

    mock_databricks.add_user(user)
    mock_databricks.add_table(table)
    mock_databricks.add_group(group1)
    mock_databricks.add_group(group2)
    mock_databricks.add_group(group3)

    writer = MockWriter.new()
    mock_databricks.get(writer.get()).run()

    calls = [
        build_user_group_in_groups(
            user,
            groups,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_schema_user_group_in_groups(
            user,
            groups,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_catalog_user_group_in_groups(
            user,
            groups,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
    ]
    writer.mocked_writer.write_entry.assert_has_calls(calls)  # type: ignore


DB_PERMISSION_TO_LEVEL = [
    (db_permission, permission_level)
    for db_permission, permission_level in DB_PERMISSION_PERMISSION_MAP.items()
    if db_permission != DBPermissionLevel.OWNERSHIP
]


@pytest.mark.parametrize(
    "db_permission,permission_level",
    DB_PERMISSION_TO_LEVEL,
    ids=[
        str(db_permission)
        for db_permission in DB_PERMISSION_PERMISSION_MAP
        if db_permission != DBPermissionLevel.OWNERSHIP
    ],
)
def test_user_permission_assignment(db_permission: DBPermissionLevel, permission_level: PermissionLevel):
    mock_databricks = DatabricksMock.new()
    catalog_name = "catalog1"
    schema_name = "schema1"
    table_name = "table1"

    user = ParsedUser(active=True, userName="user", id="12345")
    user2 = ParsedUser(active=True, userName="user2", id="6789")
    table = TestTable.new_identity_owner_all(user["userName"], table_name, schema_name, catalog_name)
    table.add_permission(user2["userName"], str(db_permission))
    mock_databricks.add_user(user)
    mock_databricks.add_user(user2)
    mock_databricks.add_table(table)
    writer = MockWriter.new()
    mock_databricks.get(writer.get()).run()
    calls = build_ownership_calls_user(user, table)
    calls.insert(
        0,
        build_direct_access_user(
            user2,
            table,
            permission_level,
            db_permissions=[str(db_permission)],
        ),
    )
    writer.mocked_writer.write_entry.assert_has_calls(calls)  # type: ignore


@pytest.mark.parametrize(
    "metastore_match,expected_metastore_id",
    [(True, "correct_metastore"), (False, "incorrect_metastore")],
    ids=["metastore id match", "metastore id doesn't match"],
)
def test_metastore_id(metastore_match: bool, expected_metastore_id: str):
    mock_databricks = DatabricksMock.new(expected_metastore_id)
    catalog_name = "catalog1"
    schema_name = "schema1"
    table_name = "table1"

    user = ParsedUser(active=True, userName="user", id="12345")
    table = TestTable.new_identity_owner_all(user["userName"], table_name, schema_name, catalog_name)

    mock_databricks.add_user(user)
    mock_databricks.add_table(table, "correct_metastore")
    writer = MockWriter.new()
    mock_databricks.get(writer.get()).run()
    calls = build_ownership_calls_user(user, table)
    if metastore_match is True:
        writer.mocked_writer.write_entry.assert_has_calls(calls)  # type: ignore
    else:
        writer.assert_write_entry_not_called()


def test_two_catalogs_same_user():
    mock_databricks = DatabricksMock.new()

    user = ParsedUser(active=True, userName="user", id="12345")
    table = TestTable.new_identity_owner_all(user["userName"], "table1", "schema1", "catalog1")
    table2 = TestTable.new_identity_owner_all(user["userName"], "table2", "schema2", "catalog2")

    mock_databricks.add_user(user)
    mock_databricks.add_table(table)
    mock_databricks.add_table(table2)

    writer = MockWriter.new()
    mock_databricks.get(writer.get()).run()

    calls = build_ownership_calls_user(user, table)
    calls.extend(build_ownership_calls_user(user, table2))
    writer.mocked_writer.write_entry.assert_has_calls(calls)  # type: ignore


def build_ownership_calls_user(user: ParsedUser, table: TestTable) -> List[_Call]:
    return [
        build_direct_access_user(
            user,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_schema_user_access(
            user,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
        build_catalog_user_access(
            user,
            table,
            PermissionLevel.FULL,
            ["OWNERSHIP"],
        ),
    ]
