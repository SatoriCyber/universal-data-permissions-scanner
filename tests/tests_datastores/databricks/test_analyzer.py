from __future__ import annotations

from authz_analyzer.datastores.databricks.service.model import (
    Group,
    GroupMeta,
    ParsedUser,
    Ref,
    ResourceType,
    ServicePrincipal,
)
from authz_analyzer.models.model import PermissionLevel
from tests.mocks.mock_writers import MockWriter
from tests.tests_datastores.databricks.generate_authz_entry import (
    build_catalog_service_principal_access,
    build_catalog_user_access,
    build_direct_access_service_principal,
    build_direct_access_user,
    build_schema_service_principal_access,
    build_schema_user_access,
    build_service_principal_catalog_group_access,
    build_service_principal_member_of_group_direct_access,
    build_service_principal_schema_group_access,
    build_user_catalog_group_access,
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

    calls = [
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


# def test_owners_group_in_group():
#     mock_databricks = DatabricksMock.new()
#     catalog_name = "catalog1"
#     schema_name = "schema1"
#     table_name = "table1"

#     user = ParsedUser(active=True, userName="user", id="12345")
#     group1 = Group(
#         displayName="Group1",
#         id="6789",
#         meta=GroupMeta(resourceType=ResourceType.GROUP),
#         members=[Ref(ref=user["id"])],
#         groups=[],
#     )
#     group2 = Group(
#         displayName="Group2",
#         id="6789",
#         meta=GroupMeta(resourceType=ResourceType.GROUP),
#         members=[],
#         groups=[Ref(ref="Groups/" + group1["id"])],
#     )
#     groups = [group1, group2]
#     table = TestTable.new_identity_owner_all(group1["displayName"], table_name, schema_name, catalog_name)

#     mock_databricks.add_user(user)
#     mock_databricks.add_table(table)
#     mock_databricks.add_group(group1)
#     mock_databricks.add_group(group2)

#     writer = MockWriter.new()
#     mock_databricks.get(writer.get()).run()

#     calls = [
#         build_user_group_in_groups(
#             user,
#             groups,
#             table,
#             PermissionLevel.FULL,
#             ["OWNERSHIP"],
#         ),
#         build_schema_user_group_in_groups(
#             user,
#             groups,
#             table,
#             PermissionLevel.FULL,
#             ["OWNERSHIP"],
#         ),
#         build_catalog_user_group_in_groups(
#             user,
#             groups,
#             table,
#             PermissionLevel.FULL,
#             ["OWNERSHIP"],
#         ),
#     ]
#     writer.mocked_writer.write_entry.assert_has_calls(calls)  # type: ignore
