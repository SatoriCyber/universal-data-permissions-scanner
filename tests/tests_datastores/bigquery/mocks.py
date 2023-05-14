from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, TypedDict
from unittest.mock import MagicMock

from google.cloud import resourcemanager_v3  # type: ignore
from google.iam.v1 import iam_policy_pb2  # type: ignore

from universal_data_permissions_scanner.datastores.bigquery.service import BigQueryService

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
    iam_roles_permissions: Dict[str, List[str]] = field(default_factory=dict)

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

        iam_client.roles = MagicMock(side_effect=self._side_effect_iam_client_roles)
        org_iam_client.roles = MagicMock(side_effect=self._side_effect_iam_client_roles)
        project_iam_client.roles = MagicMock(side_effect=self._side_effect_iam_client_roles)

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
        expected_iam_policy = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{self.project.project_id}"
        )  # pyright: ignore [reportGeneralTypeIssues]
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
        return self._side_effect_get_dataset(dataset_id).tables

    def _side_effect_get_folder(self, request: resourcemanager_v3.GetFolderRequest) -> MockedFolder:
        assert self.folder is not None
        expected = resourcemanager_v3.GetFolderRequest(name=self.folder.name)
        assert request == expected
        return self.folder

    def _side_effect_get_iam_policy_folder(self, request: iam_policy_pb2.GetIamPolicyRequest) -> MockedIam:
        assert self.folder is not None
        expected_iam_policy = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"{self.folder.name}"
        )  # pyright: ignore [reportGeneralTypeIssues]
        assert request == expected_iam_policy
        return MockedIam(bindings=self.folder.bindings)

    def _side_effect_get_organization(self, request: resourcemanager_v3.GetOrganizationRequest) -> MockedOrganization:
        assert self.organization is not None
        expected = resourcemanager_v3.GetOrganizationRequest(name=self.organization.name)
        assert request == expected
        return self.organization

    def _side_effect_get_iam_policy_organization(self, request: iam_policy_pb2.GetIamPolicyRequest) -> MockedIam:
        assert self.organization is not None
        expected_iam_policy = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"{self.organization.name}"
        )  # pyright: ignore [reportGeneralTypeIssues]
        assert request == expected_iam_policy
        return MockedIam(bindings=self.organization.bindings)

    def _side_effect_iam_client_roles(self):
        roles = MagicMock()
        roles.get = MagicMock(side_effect=self._side_effect_iam_client_get_role)
        return roles

    def _side_effect_iam_client_get_role(self, name: str):
        get_role = MagicMock()
        permissions = self.iam_roles_permissions.get(name, [])
        get_role.execute = MagicMock(return_value={"includedPermissions": permissions})
        return get_role
