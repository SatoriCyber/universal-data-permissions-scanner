from dataclasses import dataclass, field
from typing import Dict, List, Set
from unittest.mock import MagicMock, call

import pytest

from universal_data_permissions_scanner import MongoDBAtlasAuthzAnalyzer
from universal_data_permissions_scanner.datastores.mongodb.atlas.model import (
    Organization,
    OrganizationRoleName,
    OrganizationTeam,
    OrganizationTeamId,
    OrganizationUser,
    Project,
)
from universal_data_permissions_scanner.datastores.mongodb.atlas.service import AtlasService
from universal_data_permissions_scanner.datastores.mongodb.atlas.service_model import (
    ClusterConnectionStringEntry,
    ClusterEntry,
    OrganizationEntry,
    ProjectInfo,
)
from universal_data_permissions_scanner.datastores.mongodb.service import MongoDBService
from universal_data_permissions_scanner.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzNote,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)
from tests.mocks.mock_writers import MockWriter


@dataclass
class OrganizationTeamTestEntry:
    """The Organization Team Entry doesn't contains the project roles, in order for more clear testing, we will add the roles to the team"""

    team: OrganizationTeam
    roles: Set[str]

    def __hash__(self) -> int:
        return hash(self.team.id)


@dataclass
class MongoDBAtlasServiceMock:
    mocked_service: MagicMock
    organization: OrganizationEntry
    project: ProjectInfo
    cluster: ClusterEntry
    connection_string: ClusterConnectionStringEntry
    db_user: str
    db_password: str
    mongo_client: MagicMock
    database_mock: MagicMock
    database_name: str
    organization_users: List[OrganizationUser] = field(default_factory=list)
    organization_teams: Dict[OrganizationTeamId, OrganizationTeam] = field(default_factory=dict)
    project_teams: Dict[OrganizationTeamId, Set[OrganizationRoleName]] = field(default_factory=dict)

    @classmethod
    def new(
        cls,
        organization_id: str,
        organization_name: str,
        project_id: str,
        project_name: str,
        cluster_id: str,
        cluster_name: str,
        db_user: str,
        db_password: str,
        database_name: str,
        collections: List[str],
    ):
        mocked_service = MagicMock(spec=AtlasService, name="AtlasServiceMock")
        organization = OrganizationEntry(id=organization_id, name=organization_name)
        project = ProjectInfo(id=project_id, name=project_name, orgId=organization_id)
        connection_string = ClusterConnectionStringEntry(standardSrv=f"mongodb+srv://{cluster_name}.mongodb.net")
        cluster = ClusterEntry(id=cluster_id, name=cluster_name, connectionStrings=connection_string)
        mongodb_client_mock = MagicMock(spec=MongoDBService, name="MongoDBServiceMock")
        mongodb_database_mock = MagicMock(spec=MongoDBService, name="MongoDatabaseMock")

        instance = cls(
            mocked_service,
            organization,
            project,
            cluster,
            connection_string,
            db_user,
            db_password,
            mongodb_client_mock,
            mongodb_database_mock,
            database_name,
        )

        mocked_service.get_organization_info_by_id = MagicMock(
            side_effect=instance._side_effect_get_organization_by_id, name="get_organization"
        )

        mocked_service.get_project_info_by_project_name = MagicMock(
            side_effect=instance._side_effect_get_project_by_name, name="get_project"
        )

        mocked_service.get_all_organization_users_for_organization = MagicMock(
            side_effect=instance._side_effect_get_all_organization_users_for_organization,
            name="get_all_organization_users_for_organization",
        )
        mocked_service.get_all_organization_users_for_project = MagicMock(
            side_effect=instance._side_effect_get_all_organization_users_for_project
        )
        mocked_service.get_teams_for_organization = MagicMock(
            side_effect=instance._side_effect_get_all_teams_for_organization,
            name="get_all_organization_teams_for_organization",
        )
        mocked_service.get_mongodb_client = MagicMock(
            side_effect=instance._side_effect_get_mongodb_client, name="get_mongodb_client"
        )
        mocked_service.get_cluster_info_by_name = MagicMock(side_effect=instance._side_effect_get_cluster_info_by_name)
        mocked_service.get_teams_roles = MagicMock(side_effect=instance._side_effect_get_teams_roles)

        mongodb_client_mock.iter_database_connections = MagicMock(
            side_effect=instance._side_effect_iter_database_connections
        )

        mongodb_database_mock.list_collection_names = MagicMock(return_value=collections)

        return instance

    def _side_effect_get_organization_by_id(self, org_id: str):
        if org_id == self.organization["id"]:
            return self.organization
        raise Exception(f"Unexpected organization: {org_id}")

    def _side_effect_get_project_by_name(self, project_name: str):
        if project_name == self.project["name"]:
            return self.project
        raise Exception(f"Unexpected project: {project_name}")

    def _side_effect_get_all_organization_users_for_organization(self, organization: Organization):
        if self._is_expected_organization(organization):
            return self.organization_users
        raise Exception(f"Unexpected organization: {organization}")

    def _side_effect_get_all_teams_for_organization(self, organization: Organization):
        if self._is_expected_organization(organization):
            return self.organization_teams
        raise Exception(f"Unexpected organization: {organization}")

    def _side_effect_get_cluster_info_by_name(self, project_id: str, cluster_name: str):
        if self._is_expected_cluster(project_id, cluster_name):
            return self.cluster
        raise Exception(f"Unexpected cluster: {cluster_name}")

    def _side_effect_get_mongodb_client(self, connection_string: str, db_user: str, db_password: str):
        if self.connection_string["standardSrv"] != connection_string:
            raise Exception(f"Unexpected connection string: {connection_string}")
        if self.db_user != db_user:
            raise Exception(f"Unexpected db user: {db_user}")
        if self.db_password != db_password:
            raise Exception(f"Unexpected db password: {db_password}")
        return self.mongo_client

    def _side_effect_get_all_organization_users_for_project(self, project: Project):
        if self._is_expected_project(project):
            return self.organization_users
        raise Exception(f"Unexpected project: {project}")

    def _side_effect_iter_database_connections(self):
        yield (self.database_name, self.database_mock)

    def _side_effect_get_teams_roles(self, project: Project):
        if self._is_expected_project(project):
            return self.project_teams
        raise Exception(f"Unexpected project: {project}")

    def add_organization_teams(self, organization_teams_test: List[OrganizationTeamTestEntry]):
        for organization_team_test in organization_teams_test:
            self.organization_teams[organization_team_test.team.id] = organization_team_test.team
            self.project_teams[organization_team_test.team.id] = organization_team_test.roles

    def _is_expected_organization(self, organization: Organization):
        return organization.id == self.organization["id"] and organization.name == self.organization["name"]

    def _is_expected_cluster(self, project_id: str, cluster_name: str):
        return self._is_expected_project_id(project_id) and cluster_name == self.cluster["name"]

    def _is_expected_project(self, project: Project):
        return self._is_expected_project_id(project.id) and self.project["name"] == project.name

    def _is_expected_project_id(self, project_id: str):
        return self.project["id"] == project_id

    def get(self):
        return self.mocked_service


def generate_authz_entry(
    username: str,
    asset_name: List[str],
    permission: PermissionLevel,
    path: List[AuthzPathElement],
    identity_type: IdentityType,
):
    identity = Identity(id=username + "@example.com", name=username, type=identity_type)
    asset = Asset(name=asset_name, type=AssetType.COLLECTION)
    return call(AuthzEntry(identity=identity, asset=asset, permission=permission, path=path))


@pytest.mark.parametrize(
    "organization_users,organization_teams, expected_writes",
    (
        (  # test 1
            [
                OrganizationUser(
                    id="user_id_1",
                    email_address="user_id_1@example.com",
                    username="user_1",
                    teams_ids=set(),
                    roles={"ORG_BILLING_ADMIN"},
                )
            ],
            {},
            [],
        ),
        (  # test 2
            [
                OrganizationUser(
                    id="user_1",
                    email_address="user_1@example.com",
                    username="user_1",
                    teams_ids=set(),
                    roles={"ORG_OWNER"},
                )
            ],
            {},
            [
                generate_authz_entry(
                    "user_1",
                    ["db1", "collection"],
                    PermissionLevel.FULL,
                    [
                        AuthzPathElement(
                            "project_id",
                            "MyProject",
                            AuthzPathElementType.PROJECT,
                            [AuthzNote.to_generic_note("cluster MyCluster is part of project MyProject")],
                        ),
                        AuthzPathElement(
                            "MyCluster",
                            "MyCluster",
                            AuthzPathElementType.CLUSTER,
                            [AuthzNote.to_generic_note("database db1 is part of cluster MyCluster")],
                        ),
                    ],
                    IdentityType.ORG_USER,
                )
            ],
        ),
        (  # test 3
            [
                OrganizationUser(
                    id="user_1",
                    email_address="user_1@example.com",
                    username="user_1",
                    teams_ids=set(),
                    roles={"GROUP_DATA_ACCESS_READ_ONLY"},
                )
            ],
            {},
            [
                generate_authz_entry(
                    "user_1",
                    ["db1", "collection"],
                    PermissionLevel.READ,
                    [
                        AuthzPathElement(
                            "MyCluster",
                            "MyCluster",
                            AuthzPathElementType.CLUSTER,
                            [AuthzNote.to_generic_note("database db1 is part of cluster MyCluster")],
                        ),
                    ],
                    IdentityType.ORG_USER,
                )
            ],
        ),
        (  # test 4
            [
                OrganizationUser(
                    id="user_1",
                    email_address="user_1@example.com",
                    username="user_1",
                    teams_ids={"team_id_1"},
                    roles=set(),
                )
            ],
            {
                OrganizationTeamTestEntry(
                    OrganizationTeam(id="team_id_1", name="team_1"), roles={"GROUP_CLUSTER_MANAGER"}
                )
            },
            [],
        ),
        (  # test 5
            [
                OrganizationUser(
                    id="user_1",
                    email_address="user_1@example.com",
                    username="user_1",
                    teams_ids={"team_id_1"},
                    roles=set(),
                )
            ],
            {OrganizationTeamTestEntry(OrganizationTeam(id="team_id_1", name="team_1"), roles={"GROUP_OWNER"})},
            [
                generate_authz_entry(
                    "user_1",
                    ["db1", "collection"],
                    PermissionLevel.FULL,
                    [
                        AuthzPathElement(
                            "MyCluster",
                            "MyCluster",
                            AuthzPathElementType.CLUSTER,
                            [AuthzNote.to_generic_note("database db1 is part of cluster MyCluster")],
                        ),
                    ],
                    IdentityType.ORG_USER,
                )
            ],
        ),
    ),
    ids=[
        "Organization User with irrelevant role",
        "Organization User with relevant role",
        "Organization user with project role",
        "Organization user with team no relevant role",
        "Organization user with team relevant role",
    ],
)
def test_mongodb_atlas(
    organization_users: List[OrganizationUser],
    organization_teams: List[OrganizationTeamTestEntry],
    expected_writes: List[AuthzEntry],
):
    project_name = "MyProject"
    organization_name = "MyOrg"
    cluster_name = "MyCluster"
    db_user = "user"
    db_password = "Password"
    db_name = "db1"
    collections = ["collection"]

    mocked_writer = MockWriter.new()
    mocked_service = MongoDBAtlasServiceMock.new(
        "org_id",
        organization_name,
        "project_id",
        project_name,
        "cluster_id",
        cluster_name,
        db_user,
        db_password,
        db_name,
        collections,
    )
    mocked_service.organization_users = organization_users
    mocked_service.add_organization_teams(organization_teams)

    _call_analyzer(mocked_service.get(), mocked_writer.get(), db_user, db_password, project_name, cluster_name)
    if len(expected_writes) != 0:
        mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore
    else:
        mocked_writer.assert_write_entry_not_called()


def _call_analyzer(
    service: MagicMock, writer: MagicMock, db_user: str, db_password: str, project_name: str, cluster_name: str
):
    analyzer = MongoDBAtlasAuthzAnalyzer(
        atlas_service=service,
        db_user=db_user,
        db_password=db_password,
        writer=writer,
        logger=MagicMock(),
        project_name=project_name,
        cluster_name=cluster_name,
    )
    analyzer.run()
