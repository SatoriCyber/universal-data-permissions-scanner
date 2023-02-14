from enum import Enum
import pytest
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Dict, TypedDict
from unittest.mock import MagicMock, call
from authz_analyzer import BigQueryAuthzAnalyzer
from authz_analyzer.datastores.bigquery.service import BigQueryService
from authz_analyzer.models.model import Asset, AuthzEntry, AssetType, AuthzNote, AuthzNoteType, AuthzPathElement, AuthzPathElementType, Identity, IdentityType, PermissionLevel
from tests.mocks.mock_writers import MockWriter

from google.iam.v1 import iam_policy_pb2  # type: ignore

DatasetId = str
TableFqdn = str


@dataclass
class MockedDatasetId:
    dataset_id: str

    def __hash__(self) -> int:
        return hash(self.dataset_id)


class MockedBinding(TypedDict):
    role: str
    members: List[str]

@dataclass
class MockedProjectBinding:
    role: str
    members: List[str]

@dataclass
class MockedTableIamPolicy():
    bindings: List[MockedBinding]

@dataclass
class MockedTable():
    project: str
    dataset_id: str
    table_id: str
    reference: str

class EntityType(Enum):
    SPECIAL_GROUP = "specialGroup"
    OTHER = "OTHER"


class EntityId(Enum):
    PROJECT_READERS = "specialGroup"
    PROJECT_WRITERS = "projectWriters"
    PROJECT_OWNERS = "projectOwners"
    OTHER = "OTHER"

class EntityRole(Enum):
    BIGQUERY_ADMIN = "roles/bigquery.admin"
    BIGQUERY_DATA_EDITOR = "roles/bigquery.dataEditor"
    BIGQUERY_DATA_OWNER = "roles/bigquery.dataOwner"
    BIGQUERY_DATA_VIEWER = "roles/bigquery.dataViewer"
    BIGQUERY_FILTERED_DATA_VIEWER = "roles/bigquery.filteredDataViewer"
    BIGQUERY_JOB_USER = "roles/bigquery.jobUser"
    BIGQUERY_USER = "roles/bigquery.user"
    BIGQUERY_DATA_POLICY_MASKED_READER = "roles/bigquerydatapolicy.maskedReader"
    OWNER = "OWNER"
    WRITER = "WRITER"
    READER = "READER"
    OTHER = "OTHER"

@dataclass
class MockedDatasetAccessEntry:
    entity_type: EntityType
    entity_id: EntityId
    role: EntityRole


@dataclass
class MockedDataset:
    dataset_id: DatasetId
    friendly_name: Optional[str]
    access_entries: List[MockedDatasetAccessEntry]
    tables: List[MockedTable]

@dataclass
class MockedProjectIam():
    bindings: List[MockedProjectBinding]

@dataclass
class MockedProject():
    project_id: str
    parent: Optional[str]


@dataclass
class MockBigQueryService:
    project: MockedProject
    datasets: Dict[MockedDatasetId, MockedDataset]
    project_bindings: List[MockedProjectBinding] = field(default_factory=list)
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

        service = BigQueryService(
            project_id=self.project.project_id,
            bq_client=bq_client,
            project=project,
            projects_client=projects_client,
            folders_client=folders_client,
            org_client=org_client,
            iam_client=iam_client,
            org_iam_client=org_iam_client,
            project_iam_client=project_iam_client
        )          
        return service


    def _side_effect_get_iam_policy_project(self, request: iam_policy_pb2.GetIamPolicyRequest) -> MockedProjectIam:
        expected_iam_policy = iam_policy_pb2.GetIamPolicyRequest(resource=f"projects/{self.project.project_id}")
        if request == expected_iam_policy:
            return MockedProjectIam(bindings=self.project_bindings)
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
    

def generate_single_dataset() -> Dict[MockedDatasetId, MockedDataset]:
    return {
        MockedDatasetId("dataset1"): MockedDataset(
                dataset_id="dataset1", 
                friendly_name="dataset1_friendly_name", 
                access_entries=[],
                tables=[MockedTable(
                    project="project1",
                    dataset_id="dataset1",
                    table_id="table1",
                    reference="project1.dataset1.table1"
                )],
            )
    }

@pytest.mark.parametrize("project_id, datasets, project_bindings, expected_writes", [ # list of tests
    ( #test 1
        MockedProject("project1", parent=None),
        generate_single_dataset(),
        [],
        []
    ),
    ( #test 2
        MockedProject("project1", parent=None),
        generate_single_dataset(),
        [MockedProjectBinding(
            role="OWNER",
            members=["user:user1"]
        )],
        [
            call(AuthzEntry(
                asset=Asset(["project1.dataset1.table1"], AssetType.TABLE, []),
                path=[
                    AuthzPathElement(
                        id="OWNER",
                        name="OWNER",
                        type=AuthzPathElementType.ROLE,
                        notes=[AuthzNote(
                            note="Role OWNER is granted to user1",
                            type=AuthzNoteType.GENERIC
                        )],
                        db_permissions=[]
                    ),                    
                    AuthzPathElement(
                        id="project1",
                        name="project1",
                        type=AuthzPathElementType.PROJECT,
                        notes=[AuthzNote(
                            note="user1 has role OWNER",
                            type=AuthzNoteType.GENERIC
                        )],
                        db_permissions=[]
                    ),
                    AuthzPathElement(
                        id="dataset1",
                        name="dataset1_friendly_name",
                        type=AuthzPathElementType.DATASET,
                        notes=[AuthzNote(
                            note="DATASET is included in project project1",
                            type=AuthzNoteType.GENERIC
                        )],
                        db_permissions=[]
                    ), 
                    AuthzPathElement(
                        id="project1.dataset1.table1",
                        name="table1",
                        type=AuthzPathElementType.TABLE,
                        notes=[AuthzNote(
                            note="TABLE is included in dataset dataset1_friendly_name",
                            type=AuthzNoteType.GENERIC
                        )],
                        db_permissions=[]
                    ),                                       
                ],
                identity=Identity(
                    id="USER:user1",
                    type=IdentityType.USER,
                    name="user1",
                    notes=[]
                ),
                permission=PermissionLevel.FULL,

            ))
        ]
    )    
], ids=["test no project project permissions", "user with owner permission"])
def test_project_permissions(project_id: MockedProject, datasets: Dict[MockedDatasetId, MockedDataset], project_bindings: List[MockedProjectBinding], expected_writes: List[AuthzEntry]):
    service = MockBigQueryService(project_id, datasets, project_bindings=project_bindings)
    mocked_writer=MockWriter.new()
    _call_analyzer(service=service, mocked_writer=mocked_writer)
    if len(expected_writes) != 0:
        mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore
    else:
        mocked_writer.assert_write_entry_not_called()

def test_project_user():
    pass

def _call_analyzer(service: MockBigQueryService, mocked_writer: MockWriter):
    analyzer = BigQueryAuthzAnalyzer(service=service.get(), logger=MagicMock(), writer=mocked_writer.get())  # type: ignore
    analyzer.run()