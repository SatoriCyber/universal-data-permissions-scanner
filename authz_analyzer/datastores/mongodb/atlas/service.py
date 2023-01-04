"""MongoDB service.
Handle all the communication with MongoDB Atlas.
"""
from dataclasses import dataclass
from typing import Any, Dict, Set

import requests
from requests.auth import HTTPDigestAuth

from authz_analyzer.datastores.mongodb.atlas.model import DatabaseUser, OrganizationRoleName, OrganizationTeam, OrganizationTeamId, OrganizationUser
from authz_analyzer.datastores.mongodb.atlas.model import Cluster, Organization, Project



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

    def _get_resource(self, extend_uri: str) -> Dict[str, Any]:
        """Get resource from MongoDB Atlas REST API."""
        response = requests.get(BASE_API + extend_uri, auth=self.auth, timeout=10)
        response.raise_for_status()
        return response.json()

    def get_all_organizations(self):
        """Return all organizations that the API key has access to.

        Returns:
            Set[Organization]: Set of organizations.
        """
        json_response = self._get_resource("orgs")
        return {Organization(name=org["name"], id=org["id"]) for org in json_response["results"]}
    
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

