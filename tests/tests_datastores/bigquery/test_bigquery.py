from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, call

import pytest

from universal_data_permissions_scanner import BigQueryAuthzAnalyzer
from universal_data_permissions_scanner.datastores.bigquery.policy_tree import (
    IDENTITY_TYPE_MAP,
    READ_PERMISSIONS,
    ROLE_TO_PERMISSION,
    WRITE_PERMISSIONS,
)
from universal_data_permissions_scanner.models.model import IdentityType, PermissionLevel
from tests.mocks.mock_writers import MockWriter
from tests.tests_datastores.bigquery.generate_authz_entry import (
    User,
    generate_authz_entry,
    generate_authz_path_dataset,
    generate_authz_path_folder,
    generate_authz_path_organization,
    generate_authz_path_project,
    generate_authz_path_table,
    generate_authz_with_db_permissions,
)
from tests.tests_datastores.bigquery.mocks import (
    MockBigQueryService,
    MockedBinding,
    MockedDataset,
    MockedDatasetAccessEntry,
    MockedDatasetId,
    MockedFolder,
    MockedOrganization,
    MockedProject,
    MockedTable,
    MockedTableIamPolicy,
    TableFqdn,
    TypedMockedBinding,
)


@pytest.mark.parametrize(
    "project_bindings",
    [[], [MockedBinding(role="NOT_RELEVANT", members=["user:user1"])]],
    ids=["no_bindings", "no_relevant_role"],
)
def test_not_relevant_binding(project_bindings: List[MockedBinding]):
    service = generate_service_single_project(project_bindings=project_bindings)
    mocked_writer = MockWriter.new()
    _call_analyzer(service=service, mocked_writer=mocked_writer)
    mocked_writer.assert_write_entry_not_called()


def generate_service_single_project(
    project_bindings: List[MockedBinding],
    folder: Optional[MockedFolder] = None,
    organization: Optional[MockedOrganization] = None,
    datasets: Optional[Dict[MockedDatasetId, MockedDataset]] = None,
    tables_policies: Optional[Dict[TableFqdn, MockedTableIamPolicy]] = None,
):
    if datasets is None:
        datasets = generate_single_dataset()
    if tables_policies is None:
        tables_policies = {}
    parent = None
    if folder is not None:
        parent = folder.name
    project_id = MockedProject("project1", parent=parent)
    service = MockBigQueryService(
        project=project_id,
        datasets=datasets,
        project_bindings=project_bindings,
        folder=folder,
        organization=organization,
        tables_policies=tables_policies,
    )
    return service


def convert_dict_to_tuple(obj: Dict[Any, Any]):
    return list((k, v) for k, v in obj.items())


@pytest.mark.parametrize(
    "user_type, identity_type",
    convert_dict_to_tuple(IDENTITY_TYPE_MAP),
    ids=IDENTITY_TYPE_MAP.keys(),
)
def test_project_identity_types(user_type: str, identity_type: IdentityType):
    user = User(f"{user_type}:user1", "user1", identity_type)
    role = "OWNER"
    project_bindings = [MockedBinding(role=role, members=[user.id])]
    expected_writes = [call(generate_authz_entry(user, role, PermissionLevel.FULL, generate_authz_path_project))]
    service = generate_service_single_project(project_bindings=project_bindings)

    _run_and_assert(service=service, expected_writes=expected_writes)


@pytest.mark.parametrize(
    "role, permission_level",
    convert_dict_to_tuple(ROLE_TO_PERMISSION),
    ids=ROLE_TO_PERMISSION.keys(),
)
def test_roles(role: str, permission_level: PermissionLevel):
    user = User("user:user1", "user1", IdentityType.USER)
    project_bindings = [MockedBinding(role=role, members=[user.id])]
    expected_writes = [call(generate_authz_entry(user, role, permission_level, generate_authz_path_project))]
    service = generate_service_single_project(project_bindings=project_bindings)

    _run_and_assert(service=service, expected_writes=expected_writes)


def test_folder():
    user = User("user:user1", "user1", IdentityType.USER)
    user_id = "user:user1"
    role = "OWNER"
    folder_bindings = [MockedBinding(role=role, members=[user_id])]
    folder = MockedFolder(name="folders/folder1", bindings=folder_bindings, display_name="folder1_display_name")
    expected_writes = [call(generate_authz_entry(user, role, PermissionLevel.FULL, generate_authz_path_folder))]
    service = generate_service_single_project(
        project_bindings=[],
        folder=folder,
    )

    _run_and_assert(service=service, expected_writes=expected_writes)


def test_organization():
    user = User("user:user1", "user1", IdentityType.USER)
    org_bindings = [MockedBinding(role="OWNER", members=[user.id])]
    organization = MockedOrganization("organizations/1234", display_name="1234", bindings=org_bindings)
    folder = MockedFolder(
        name="folders/folder1", bindings=[], display_name="folder1_display_name", parent="organizations/1234"
    )
    expected_writes = [
        call(generate_authz_entry(user, "OWNER", PermissionLevel.FULL, generate_authz_path_organization))
    ]
    service = generate_service_single_project(project_bindings=[], folder=folder, organization=organization)

    _run_and_assert(service=service, expected_writes=expected_writes)


def test_dataset_iam():
    user = User("user:user1", "user1", IdentityType.USER)
    role = "OWNER"
    expected_writes = [call(generate_authz_entry(user, role, PermissionLevel.FULL, generate_authz_path_dataset))]
    datasets = generate_single_dataset([MockedDatasetAccessEntry(role=role, entity_type="user", entity_id=user.name)])
    service = generate_service_single_project(project_bindings=[], datasets=datasets)

    _run_and_assert(service=service, expected_writes=expected_writes)


def test_table_iam():
    user = User("user:user1", "user1", IdentityType.USER)
    role = "OWNER"
    table_id = "project1.dataset1.table1"
    table_policies = {table_id: MockedTableIamPolicy(bindings=[TypedMockedBinding(role=role, members=[user.id])])}
    expected_writes = [call(generate_authz_entry(user, role, PermissionLevel.FULL, generate_authz_path_table))]

    datasets = generate_single_dataset()
    service = generate_service_single_project(project_bindings=[], datasets=datasets, tables_policies=table_policies)
    _run_and_assert(service=service, expected_writes=expected_writes)


def test_custom_role_not_relevant_with_table():
    user = User("user:user1", "user1", IdentityType.USER)
    role = "CUSTOM_ROLE"
    table_id = "project1.dataset1.table1"
    permissions = ["not_relevant"]
    table_policies = {table_id: MockedTableIamPolicy(bindings=[TypedMockedBinding(role=role, members=[user.id])])}
    roles = {role: permissions}

    datasets = generate_single_dataset()
    service = generate_service_single_project(project_bindings=[], datasets=datasets, tables_policies=table_policies)
    service.iam_roles_permissions = roles
    mocked_writer = MockWriter.new()
    _call_analyzer(service=service, mocked_writer=mocked_writer)
    mocked_writer.assert_write_entry_not_called()


@pytest.mark.parametrize("permission", READ_PERMISSIONS)
def test_custom_role_with_table_read_only(permission: str):
    user = User("user:user1", "user1", IdentityType.USER)
    role = "CUSTOM_ROLE"
    table_id = "project1.dataset1.table1"
    table_policies = {table_id: MockedTableIamPolicy(bindings=[TypedMockedBinding(role=role, members=[user.id])])}
    permissions = [permission]
    roles = {role: permissions}

    datasets = generate_single_dataset()
    service = generate_service_single_project(project_bindings=[], datasets=datasets, tables_policies=table_policies)
    service.iam_roles_permissions = roles
    expected_writes = [
        call(
            generate_authz_with_db_permissions(user, role, PermissionLevel.READ, generate_authz_path_table, permissions)
        )
    ]
    _run_and_assert(service=service, expected_writes=expected_writes)


@pytest.mark.parametrize("permission", WRITE_PERMISSIONS)
def test_custom_role_with_table_write_only(permission: str):
    user = User("user:user1", "user1", IdentityType.USER)
    role = "CUSTOM_ROLE"
    table_id = "project1.dataset1.table1"
    table_policies = {table_id: MockedTableIamPolicy(bindings=[TypedMockedBinding(role=role, members=[user.id])])}
    permissions = [permission]
    roles = {role: permissions}

    datasets = generate_single_dataset()
    service = generate_service_single_project(project_bindings=[], datasets=datasets, tables_policies=table_policies)
    service.iam_roles_permissions = roles
    expected_writes = [
        call(
            generate_authz_with_db_permissions(
                user, role, PermissionLevel.WRITE, generate_authz_path_table, permissions
            )
        )
    ]
    _run_and_assert(service=service, expected_writes=expected_writes)


def test_custom_role_with_table_read_write():
    user = User("user:user1", "user1", IdentityType.USER)
    role = "CUSTOM_ROLE"
    table_id = "project1.dataset1.table1"
    table_policies = {table_id: MockedTableIamPolicy(bindings=[TypedMockedBinding(role=role, members=[user.id])])}
    permissions = ["bigquery.dataPolicies.maskedGet", "bigquery.dataPolicies.maskedSet"]
    roles = {role: permissions}

    datasets = generate_single_dataset()
    service = generate_service_single_project(project_bindings=[], datasets=datasets, tables_policies=table_policies)
    service.iam_roles_permissions = roles
    expected_writes = [
        call(
            generate_authz_with_db_permissions(
                user, role, PermissionLevel.WRITE, generate_authz_path_table, permissions
            )
        )
    ]
    _run_and_assert(service=service, expected_writes=expected_writes)


def test_custom_role_with_table_double_read():
    user = User("user:user1", "user1", IdentityType.USER)
    role = "CUSTOM_ROLE"
    table_id = "project1.dataset1.table1"
    table_policies = {table_id: MockedTableIamPolicy(bindings=[TypedMockedBinding(role=role, members=[user.id])])}
    permissions = ["bigquery.dataPolicies.maskedGet", "bigquery.tables.getData"]
    roles = {role: permissions}

    datasets = generate_single_dataset()
    service = generate_service_single_project(project_bindings=[], datasets=datasets, tables_policies=table_policies)
    service.iam_roles_permissions = roles
    expected_writes = [
        call(
            generate_authz_with_db_permissions(user, role, PermissionLevel.READ, generate_authz_path_table, permissions)
        )
    ]
    _run_and_assert(service=service, expected_writes=expected_writes)


def test_custom_role_with_table_double_write():
    user = User("user:user1", "user1", IdentityType.USER)
    role = "CUSTOM_ROLE"
    table_id = "project1.dataset1.table1"
    table_policies = {table_id: MockedTableIamPolicy(bindings=[TypedMockedBinding(role=role, members=[user.id])])}
    permissions = ["bigquery.dataPolicies.maskedSet", "bigquery.tables.delete"]
    roles = {role: permissions}

    datasets = generate_single_dataset()
    service = generate_service_single_project(project_bindings=[], datasets=datasets, tables_policies=table_policies)
    service.iam_roles_permissions = roles
    expected_writes = [
        call(
            generate_authz_with_db_permissions(
                user, role, PermissionLevel.WRITE, generate_authz_path_table, permissions
            )
        )
    ]
    _run_and_assert(service=service, expected_writes=expected_writes)


def test_custom_role_with_table_read_with_one_not_relevant():
    user = User("user:user1", "user1", IdentityType.USER)
    role = "CUSTOM_ROLE"
    table_id = "project1.dataset1.table1"
    table_policies = {table_id: MockedTableIamPolicy(bindings=[TypedMockedBinding(role=role, members=[user.id])])}
    permissions = ["bigquery.dataPolicies.maskedGet", "not_relevant_permission"]
    roles = {role: permissions}
    datasets = generate_single_dataset()
    service = generate_service_single_project(project_bindings=[], datasets=datasets, tables_policies=table_policies)
    service.iam_roles_permissions = roles
    expected_writes = [
        call(
            generate_authz_with_db_permissions(
                user, role, PermissionLevel.READ, generate_authz_path_table, ["bigquery.dataPolicies.maskedGet"]
            )
        )
    ]
    _run_and_assert(service=service, expected_writes=expected_writes)


@pytest.mark.parametrize(
    "permissions, permission_level",
    [
        (["bigquery.dataPolicies.maskedGet"], PermissionLevel.READ),
        (["bigquery.dataPolicies.maskedSet"], PermissionLevel.WRITE),
    ],
    ids=["READ", "WRITE"],
)
def test_custom_role_with_organization(permissions: List[str], permission_level: PermissionLevel):
    user = User("user:user1", "user1", IdentityType.USER)
    role = "organizations/CUSTOM_ROLE"

    roles = {role: permissions}
    org_bindings = [MockedBinding(role=role, members=[user.id])]
    organization = MockedOrganization("organizations/1234", display_name="1234", bindings=org_bindings)

    datasets = generate_single_dataset()
    service = generate_service_single_project(
        project_bindings=[],
        datasets=datasets,
        folder=MockedFolder(
            name="folders/folder1", bindings=[], display_name="folder1_display_name", parent="organizations/1234"
        ),
        organization=organization,
    )
    service.iam_roles_permissions = roles
    expected_writes = [
        call(
            generate_authz_with_db_permissions(
                user, role, permission_level, generate_authz_path_organization, permissions
            )
        )
    ]
    _run_and_assert(service=service, expected_writes=expected_writes)


@pytest.mark.parametrize(
    "permissions, permission_level",
    [
        (["bigquery.dataPolicies.maskedGet"], PermissionLevel.READ),
        (["bigquery.dataPolicies.maskedSet"], PermissionLevel.WRITE),
    ],
    ids=["READ", "WRITE"],
)
def test_custom_role_with_project(permissions: List[str], permission_level: PermissionLevel):
    user = User("user:user1", "user1", IdentityType.USER)
    role = "organizations/CUSTOM_ROLE"

    roles = {role: permissions}
    project_bindings = [MockedBinding(role=role, members=[user.id])]

    datasets = generate_single_dataset()
    service = generate_service_single_project(project_bindings=project_bindings, datasets=datasets)
    service.iam_roles_permissions = roles
    expected_writes = [
        call(generate_authz_with_db_permissions(user, role, permission_level, generate_authz_path_project, permissions))
    ]
    _run_and_assert(service=service, expected_writes=expected_writes)


def _run_and_assert(service: MockBigQueryService, expected_writes: List[Any]):
    mocked_writer = MockWriter.new()
    _call_analyzer(service=service, mocked_writer=mocked_writer)
    mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore


def _call_analyzer(service: MockBigQueryService, mocked_writer: MockWriter):
    analyzer = BigQueryAuthzAnalyzer(service=service.get(), logger=MagicMock(), writer=mocked_writer.get())  # type: ignore
    analyzer.run()


def generate_single_dataset(
    access_entries: Optional[List[MockedDatasetAccessEntry]] = None,
) -> Dict[MockedDatasetId, MockedDataset]:
    if access_entries is None:
        access_entries = []
    return {
        MockedDatasetId("dataset1"): MockedDataset(
            dataset_id="dataset1",
            friendly_name="dataset1_friendly_name",
            access_entries=access_entries,
            tables=[
                MockedTable(
                    project="project1", dataset_id="dataset1", table_id="table1", reference="project1.dataset1.table1"
                )
            ],
        )
    }
