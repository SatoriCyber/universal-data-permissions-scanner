"""MongoDB service.
Handle all the communication with MongoDB Atlas.
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Set

import requests
from pymongo import MongoClient  # pylint: disable=import-error
from requests.auth import HTTPDigestAuth

from universal_data_permissions_scanner.datastores.mongodb.atlas.model import (
    Cluster,
    CustomRole,
    DatabaseUser,
    Organization,
    OrganizationRoleName,
    OrganizationTeam,
    OrganizationTeamId,
    OrganizationUser,
    Project,
)
from universal_data_permissions_scanner.datastores.mongodb.atlas.service_model import (
    ClusterEntry,
    CustomRoleEntry,
    OrganizationEntry,
    ProjectInfo,
)
from universal_data_permissions_scanner.datastores.mongodb.service import MongoDBService

BASE_API = "https://cloud.mongodb.com/api/atlas/v1.0/"


@dataclass
class AtlasService:
    """Analyze authorization for MongoDB.
    MongoDB Python client doesn't support Atlas admin API.
    Need to access MongoDB Atlas REST directly.
    Need to enable it https://www.mongodb.com/docs/atlas/configure-api-access/
    https://www.mongodb.com/docs/atlas/configure-api-access/#std-label-create-org-api-key
    Organization read only.
    """

    auth: HTTPDigestAuth

    @classmethod
    def connect(cls, atlas_user: str, atlas_user_key: str):
        """Connect to the MongoDB atlas.
        Tries to authenticate with the provided credentials to the base API.
        Because Atlas is REST API, there is no notion of a connection.
        """
        auth = HTTPDigestAuth(atlas_user, atlas_user_key)
        analyzer = cls(auth)
        analyzer._get_resource("")
        return analyzer

    def _get_resource(self, extend_uri: str):
        """Get resource from MongoDB Atlas REST API."""
        response = requests.get(BASE_API + extend_uri, auth=self.auth, timeout=10)
        response.raise_for_status()
        return response.json()

    def get_organization_info_by_id(self, organization_id: str):
        """Get organization info by id."""
        json_response: OrganizationEntry = self._get_resource(f"orgs/{organization_id}")
        return json_response

    def get_all_organization_users_for_organization(self, organization: Organization):
        """Get all organization users for organization."""
        json_response = self._get_resource(f"orgs/{organization.id}/users")
        return {OrganizationUser.build_from_response(entry) for entry in json_response["results"]}

    def get_teams_for_organization(self, organization: Organization):
        """Get all organization teams for organization."""
        json_response = self._get_resource(f"orgs/{organization.id}/teams")
        return {entry["id"]: OrganizationTeam.build_from_response(entry) for entry in json_response["results"]}

    def get_all_projects(self):
        """Get all projects in the organization."""
        json_response = self._get_resource("groups")
        return {Project(id=project["id"], name=project["name"]) for project in json_response["results"]}

    def get_all_project_for_organization(self, organization: Organization):
        """Get all projects for organization."""
        json_response = self._get_resource(f"orgs/{organization.id}/groups")
        return {Project(id=project["id"], name=project["name"]) for project in json_response["results"]}

    def get_all_organization_users_for_project(self, project: Project):
        """Get all users for project."""
        json_response = self._get_resource(f"groups/{project.id}/users")
        return {OrganizationUser.build_from_response(entry) for entry in json_response["results"]}

    def get_teams_roles(self, project: Project):
        """Get all teams and their roles for specific project."""
        json_response = self._get_resource(f"groups/{project.id}/teams")
        results: Dict[OrganizationTeamId, Set[OrganizationRoleName]] = {}
        for entry in json_response["results"]:
            results[entry["teamId"]] = entry["roleNames"]

        return results

    def get_all_clusters_for_project(self, project: Project):
        """Get all clusters for project."""
        json_response = self._get_resource(f"groups/{project.id}/clusters")
        return {Cluster.build_from_response(cluster) for cluster in json_response["results"]}

    def get_all_db_users_for_project(self, project: Project):
        """Get all users for project."""
        json_response = self._get_resource(f"groups/{project.id}/databaseUsers")
        return {DatabaseUser.build_from_response(entry) for entry in json_response["results"]}

    def get_custom_roles_by_project(self, project: Project) -> Dict[str, CustomRole]:
        """Get all custom roles for project."""
        json_response: List[CustomRoleEntry] = self._get_resource(f"groups/{project.id}/customDBRoles/roles")
        return {entry["roleName"]: CustomRole.build_custom_role_from_response(entry) for entry in json_response}

    def get_project_info_by_project_name(self, project_id: str):
        """Get project info by project name."""
        json_response: ProjectInfo = self._get_resource(f"groups/byName/{project_id}")
        return json_response

    def get_cluster_info_by_name(self, project_id: str, cluster_name: str):
        """Get cluster info by cluster name."""
        json_response: ClusterEntry = self._get_resource(f"groups/{project_id}/clusters/{cluster_name}")
        return json_response

    @staticmethod
    def get_mongodb_client(connection_string: str, db_user: str, db_password: str, **kwargs: Any) -> MongoDBService:
        """Get MongoDB connection."""
        return MongoDBService(
            MongoClient(
                connection_string,
                username=db_user,
                password=db_password,
                tlsAllowInvalidCertificates=True,
                tls=True,
                **kwargs,
            )
        )
