import pytest
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional, Dict, TypedDict
from unittest.mock import MagicMock, call
from authz_analyzer import BigQueryAuthzAnalyzer
from authz_analyzer.datastores.bigquery.service import BigQueryService
from authz_analyzer.models.model import (
    Asset,
    AuthzEntry,
    AssetType,
    AuthzNote,
    AuthzNoteType,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)
from tests.mocks.mock_writers import MockWriter

from google.iam.v1 import iam_policy_pb2  # type: ignore
from google.cloud import resourcemanager_v3  # type: ignore

DatasetId = str
TableFqdn = str


@dataclass
class MockedDatasetId:
    dataset_id: str

    def __hash__(self) -> int:
        return hash(self.dataset_id)


class TypedMockedBinding(TypedDict):
    role: str
    members: List[str]


@dataclass
class MockedBinding:
    role: str
    members: List[str]


@dataclass
class MockedTableIamPolicy:
    bindings: List[TypedMockedBinding]


@dataclass
class MockedTable:
    project: str
    dataset_id: str
    table_id: str
    reference: str


@dataclass
class MockedDatasetAccessEntry:
    entity_type: str
    entity_id: str
    role: str


@dataclass
class MockedDataset:
    dataset_id: DatasetId
    friendly_name: Optional[str]
    access_entries: List[MockedDatasetAccessEntry]
    tables: List[MockedTable]


@dataclass
class MockedIam:
    bindings: List[MockedBinding]


@dataclass
class MockedProject:
    project_id: str
    parent: Optional[str]


@dataclass
class MockedFolder:
    name: str
    display_name: str
    parent: Optional[str] = None
    bindings: List[MockedBinding] = field(default_factory=list)


@dataclass
class MockedOrganization:
    name: str
    display_name: str
    bindings: List[MockedBinding] = field(default_factory=list)


@dataclass
class MockBigQueryService:
    project: MockedProject
    datasets: Dict[MockedDatasetId, MockedDataset]
    folder: Optional[MockedFolder] = None
    organization: Optional[MockedOrganization] = None
    project_bindings: List[MockedBinding] = field(default_factory=list)
    tables_policies: Dict[TableFqdn, MockedTableIamPolicy] = field(default_factory=dict)

    def get(self) -> BigQueryService:
        bq_client = MagicMock()
        project = MagicMock()
        projects_client = MagicMock()
        folders_client = MagicMock()
        org_client = MagicMock()
        iam_client = MagicMock()
        org_iam_client = MagicMock()
        project_iam_client = MagicMock()

        project.parent = self.project.parent
        project.name = self.project.project_id
        project.project_id = self.project.project_id

        bq_client.list_datasets = MagicMock(side_effect=self._side_effect_list_datasets)
        bq_client.get_dataset = MagicMock(side_effect=self._side_effect_get_dataset)
        bq_client.list_tables = MagicMock(side_effect=self._side_effect_list_tables)
        bq_client.get_iam_policy = MagicMock(side_effect=self._side_effect_get_iam_policy_bq_client)

        projects_client.get_iam_policy = MagicMock(side_effect=self._side_effect_get_iam_policy_project)

        folders_client.get_folder = MagicMock(side_effect=self._side_effect_get_folder)
        folders_client.get_iam_policy = MagicMock(side_effect=self._side_effect_get_iam_policy_folder)

        org_client.get_organization = MagicMock(side_effect=self._side_effect_get_organization)
        org_client.get_iam_policy = MagicMock(side_effect=self._side_effect_get_iam_policy_organization)

        service = BigQueryService(
            project_id=self.project.project_id,
            bq_client=bq_client,
            project=project,
            projects_client=projects_client,
            folders_client=folders_client,
            org_client=org_client,
            iam_client=iam_client,
            org_iam_client=org_iam_client,
            project_iam_client=project_iam_client,
        )
        return service

    def _side_effect_get_iam_policy_project(self, request: iam_policy_pb2.GetIamPolicyRequest) -> MockedIam:
        expected_iam_policy = iam_policy_pb2.GetIamPolicyRequest(resource=f"projects/{self.project.project_id}")
        if request == expected_iam_policy:
            return MockedIam(bindings=self.project_bindings)
        raise ValueError(f"Unexpected request: {request}")

    def _side_effect_get_iam_policy_bq_client(self, request: str) -> MockedTableIamPolicy:
        return self.tables_policies.get(request, MockedTableIamPolicy(bindings=[]))

    def _side_effect_list_datasets(self) -> Iterable[MockedDatasetId]:
        return self.datasets.keys()

    def _side_effect_get_dataset(self, dataset_id: str) -> MockedDataset:
        try:
            mocked_dataset = MockedDatasetId(dataset_id=dataset_id)
            return self.datasets[mocked_dataset]
        except KeyError as err:
            raise ValueError(f"Dataset {dataset_id} is not defined") from err

    def _side_effect_list_tables(self, dataset_id: str) -> Iterable[MockedTable]:
        try:
            mocked_dataset = MockedDatasetId(dataset_id=dataset_id)
            return self.datasets[mocked_dataset].tables
        except KeyError as err:
            raise ValueError(f"Dataset {dataset_id} is not defined") from err

    def _side_effect_get_folder(self, request: resourcemanager_v3.GetFolderRequest) -> MockedFolder:
        if self.folder is None:
            raise ValueError("Folder is not defined")
        expected = resourcemanager_v3.GetFolderRequest(name=self.folder.name)
        if request == expected:
            return self.folder
        raise ValueError(f"Unexpected request: {request}")

    def _side_effect_get_iam_policy_folder(self, request: iam_policy_pb2.GetIamPolicyRequest) -> MockedIam:
        if self.folder is None:
            raise ValueError("Folder is not defined")
        expected_iam_policy = iam_policy_pb2.GetIamPolicyRequest(resource=f"{self.folder.name}")
        if request == expected_iam_policy:
            return MockedIam(bindings=self.folder.bindings)
        raise ValueError(f"Unexpected request: {request}")

    def _side_effect_get_organization(self, request: resourcemanager_v3.GetOrganizationRequest) -> MockedOrganization:
        if self.organization is None:
            raise ValueError("Organization is not defined")
        expected = resourcemanager_v3.GetOrganizationRequest(name=self.organization.name)
        assert request == expected
        return self.organization

    def _side_effect_get_iam_policy_organization(self, request: iam_policy_pb2.GetIamPolicyRequest) -> MockedIam:
        if self.organization is None:
            raise ValueError("Folder is not defined")
        expected_iam_policy = iam_policy_pb2.GetIamPolicyRequest(resource=f"{self.organization.name}")
        assert request == expected_iam_policy
        return MockedIam(bindings=self.organization.bindings)


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


def generate_authz_path_element(
    authz_path_element_id: str, name: str, authz_path_element_type: AuthzPathElementType, note: str
) -> AuthzPathElement:
    return AuthzPathElement(
        id=authz_path_element_id,
        name=name,
        type=authz_path_element_type,
        notes=[AuthzNote(note=note, type=AuthzNoteType.GENERIC)],
        db_permissions=[],
    )


def generate_authz_path_element_role(granted_to: str, role: str) -> AuthzPathElement:
    return generate_authz_path_element(role, role, AuthzPathElementType.ROLE, f"Role {role} is granted to {granted_to}")


def generate_authz_path_element_project(note: str) -> AuthzPathElement:
    return generate_authz_path_element("project1", "project1", AuthzPathElementType.PROJECT, note)


def generate_authz_path_element_dataset(note: str) -> AuthzPathElement:
    return generate_authz_path_element("dataset1", "dataset1_friendly_name", AuthzPathElementType.DATASET, note)


def generate_authz_path_element_table() -> AuthzPathElement:
    return generate_authz_path_element(
        "project1.dataset1.table1",
        "table1",
        AuthzPathElementType.TABLE,
        "table table1 is included in dataset dataset1_friendly_name",
    )


def generate_authz_path_element_folder(note: str) -> AuthzPathElement:
    return generate_authz_path_element("folders/folder1", "folder1_display_name", AuthzPathElementType.FOLDER, note)


def generate_authz_path_element_organization(note: str) -> AuthzPathElement:
    return generate_authz_path_element("organizations/1234", "1234", AuthzPathElementType.ORGANIZATION, note)


def generate_authz_path_dataset(granted_to: str, role: str) -> List[AuthzPathElement]:
    return [
        generate_authz_path_element_role(granted_to, role),
        generate_authz_path_element_dataset(f"{granted_to} has role {role}"),
        generate_authz_path_element_table(),
    ]


def generate_authz_path_project(granted_to: str, role: str) -> List[AuthzPathElement]:
    return [
        generate_authz_path_element_role(granted_to, role),
        generate_authz_path_element_project(f"{granted_to} has role {role}"),
        generate_authz_path_element_dataset("dataset dataset1_friendly_name is included in project project1"),
        generate_authz_path_element_table(),
    ]


def generate_authz_path_folder(granted_to: str) -> List[AuthzPathElement]:
    role = "OWNER"
    return [
        generate_authz_path_element_role(granted_to, role),
        generate_authz_path_element_folder(f"{granted_to} has role {role}"),
        generate_authz_path_element_project("project project1 is included in folder folder1_display_name"),
        generate_authz_path_element_dataset("dataset dataset1_friendly_name is included in project project1"),
        generate_authz_path_element_table(),
    ]


def generate_authz_path_organization(granted_to: str) -> List[AuthzPathElement]:
    role = "OWNER"
    return [
        generate_authz_path_element_role(granted_to, role),
        generate_authz_path_element_organization(f"{granted_to} has role {role}"),
        generate_authz_path_element_folder("folder folder1_display_name is included in organization 1234"),
        generate_authz_path_element_project("project project1 is included in folder folder1_display_name"),
        generate_authz_path_element_dataset("dataset dataset1_friendly_name is included in project project1"),
        generate_authz_path_element_table(),
    ]


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
):
    if datasets is None:
        datasets = generate_single_dataset()
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
    )
    return service


@pytest.mark.parametrize(
    "user_id, identity_type",
    [  # list of tests
        ("user:user1", IdentityType.USER),
        ("userByEmail:user1@example.com", IdentityType.USER),
        ("serviceAccount:sa1", IdentityType.SERVICE_ACCOUNT),
        ("group:group1", IdentityType.GROUP),
        ("domain:wwww.satoricyber.com", IdentityType.CLOUD_IDENTITY_DOMAIN),
    ],
    ids=["user", "user by email", "service account", "group", "domain"],
)
def test_project_identity_types(user_id: str, identity_type: IdentityType):
    role = "OWNER"
    project_bindings = [MockedBinding(role=role, members=[user_id])]
    username = user_id.split(":")[1]
    expected_writes = [
        call(
            AuthzEntry(
                asset=Asset(["project1.dataset1.table1"], AssetType.TABLE, []),
                path=generate_authz_path_project(username, role),
                identity=Identity(id=user_id, type=identity_type, name=username, notes=[]),
                permission=PermissionLevel.FULL,
            )
        )
    ]

    service = generate_service_single_project(project_bindings=project_bindings)
    _run_and_assert(service=service, expected_writes=expected_writes)


@pytest.mark.parametrize(
    "role, permission_level",
    [
        ("roles/viewer", PermissionLevel.READ),
        ("roles/editor", PermissionLevel.WRITE),
        ("roles/owner", PermissionLevel.FULL),
        ("roles/bigquery.admin", PermissionLevel.FULL),
        ("roles/bigquery.dataEditor", PermissionLevel.WRITE),
        ("roles/bigquery.dataOwner", PermissionLevel.FULL),
        ("roles/bigquery.dataViewer", PermissionLevel.READ),
        ("roles/bigquery.filteredDataViewer", PermissionLevel.READ),
        ("roles/bigquery.jobUser", PermissionLevel.WRITE),
        ("roles/bigquery.user", PermissionLevel.READ),
        ("roles/bigquerydatapolicy.maskedReader", PermissionLevel.READ),
        ("OWNER", PermissionLevel.FULL),
        ("WRITER", PermissionLevel.WRITE),
        ("READER", PermissionLevel.READ),
    ],
    ids=[
        "roles/viewer",
        "roles/editor",
        "roles/owner",
        "roles/bigquery.admin",
        "roles/bigquery.dataEditor",
        "roles/bigquery.dataOwner",
        "roles/bigquery.dataViewer",
        "roles/bigquery.filteredDataViewer",
        "roles/bigquery.jobUser",
        "roles/bigquery.user",
        "roles/bigquerydatapolicy.maskedReader",
        "OWNER",
        "WRITER",
        "READER",
    ],
)
def test_roles(role: str, permission_level: PermissionLevel):
    user_id = "user:user1"
    identity_type = IdentityType.USER
    project_bindings = [MockedBinding(role=role, members=[user_id])]
    username = user_id.split(":")[1]
    expected_writes = [
        call(
            AuthzEntry(
                asset=Asset(["project1.dataset1.table1"], AssetType.TABLE, []),
                path=generate_authz_path_project(username, role),
                identity=Identity(id=user_id, type=identity_type, name=username, notes=[]),
                permission=permission_level,
            )
        )
    ]

    service = generate_service_single_project(project_bindings=project_bindings)
    _run_and_assert(service=service, expected_writes=expected_writes)


def test_folder():
    user_id = "user:user1"
    identity_type = IdentityType.USER
    folder_bindings = [MockedBinding(role="OWNER", members=[user_id])]
    username = user_id.split(":")[1]
    expected_writes = [
        call(
            AuthzEntry(
                asset=Asset(["project1.dataset1.table1"], AssetType.TABLE, []),
                path=generate_authz_path_folder(username),
                identity=Identity(id=user_id, type=identity_type, name=username, notes=[]),
                permission=PermissionLevel.FULL,
            )
        )
    ]

    service = generate_service_single_project(
        project_bindings=[],
        folder=MockedFolder(name="folders/folder1", bindings=folder_bindings, display_name="folder1_display_name"),
    )
    _run_and_assert(service=service, expected_writes=expected_writes)


def test_org_with_folder():
    user_id = "user:user1"
    identity_type = IdentityType.USER
    org_bindings = [MockedBinding(role="OWNER", members=[user_id])]
    organization = MockedOrganization("organizations/1234", display_name="1234", bindings=org_bindings)
    username = user_id.split(":")[1]
    expected_writes = [
        call(
            AuthzEntry(
                asset=Asset(["project1.dataset1.table1"], AssetType.TABLE, []),
                path=generate_authz_path_organization(username),
                identity=Identity(id=user_id, type=identity_type, name=username, notes=[]),
                permission=PermissionLevel.FULL,
            )
        )
    ]

    service = generate_service_single_project(
        project_bindings=[],
        folder=MockedFolder(
            name="folders/folder1", bindings=[], display_name="folder1_display_name", parent="organizations/1234"
        ),
        organization=organization,
    )
    _run_and_assert(service=service, expected_writes=expected_writes)


def test_dataset_iam():
    user_id = "user:user1"
    username = user_id.split(":")[1]
    role = "OWNER"
    identity_type = IdentityType.USER
    expected_writes = [
        call(
            AuthzEntry(
                asset=Asset(["project1.dataset1.table1"], AssetType.TABLE, []),
                path=generate_authz_path_dataset(username, role),
                identity=Identity(id=user_id, type=identity_type, name=username, notes=[]),
                permission=PermissionLevel.FULL,
            )
        )
    ]

    datasets = generate_single_dataset([MockedDatasetAccessEntry(role=role, entity_type="user", entity_id=username)])
    service = generate_service_single_project(project_bindings=[], datasets=datasets)
    _run_and_assert(service=service, expected_writes=expected_writes)


def _run_and_assert(service: MockBigQueryService, expected_writes: List[Any]):
    mocked_writer = MockWriter.new()
    _call_analyzer(service=service, mocked_writer=mocked_writer)
    mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore


def _call_analyzer(service: MockBigQueryService, mocked_writer: MockWriter):
    analyzer = BigQueryAuthzAnalyzer(service=service.get(), logger=MagicMock(), writer=mocked_writer.get())  # type: ignore
    analyzer.run()
