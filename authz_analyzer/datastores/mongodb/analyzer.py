"""Analyze authorization for MongoDB.

The analyzer support two implementations:
- MongoDB Atlas - which is MongoDB managed service
- MongoDB native

MongoDB Atlas supports two types of identities:
    Atlas users - Users who can access Atlas, called Organization users.
    Database users - Users who can access the database, called Database users.

Atlas users:
Users are defined in the organization level.
Users can be assigned to teams.
Users and teams are assigned with roles.
There are two types of users:
    Local users - users who are defined in the Atlas.
    Federated users - users who are defined in the external identity provider.
There are two types of roles:
    Organization roles - Roles that are defined in the organization level.
    Project roles - Roles that are defined in the project level.
Atlas only allow to provide access to project or organization,
        cluster, database or collection level isn't supported.

Database users:
Users are defined in the project level.
Type of users:
    Local users - users who are defined in the Atlas.
    Cloud users - AWS IAM users.
    LDAP users - users who are defined in the LDAP.
    X.509 users - users who are defined in the X.509.
Roles have scope:
    Project - All clusters in the project.
    Database - All databases in the cluster
    Collection - All collections in the database.
Atlas also allows to limit the access to specific cluster.
"""
from logging import Logger
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Union

from pymongo import MongoClient


from authz_analyzer.datastores.mongodb.atlas.service import AtlasService
from authz_analyzer.datastores.mongodb.atlas.model import Cluster, Organization, Project
from authz_analyzer.datastores.mongodb.atlas.permission_resolvers import PermissionScope, resolve_organization_role, resolve_project_role, resolve_database_role
from authz_analyzer.datastores.mongodb.atlas.model import (
    OrganizationRoleName,
    OrganizationTeam,
    OrganizationUser,
    DatabaseRole,
)
from authz_analyzer.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import OutputFormat, BaseWriter
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE
from authz_analyzer.writers.get_writers import get_writer


PermissionOrganizationUserMap = Dict[PermissionLevel, Set[OrganizationUser]]

@dataclass
class MongoDBAuthzAnalyzer:
    """Analyze authorization for MongoDB.
    MongoDB Python client doesn't support Atlas admin API.
    Need to access MongoDB Atlas REST directly.
    Need to enable it https://www.mongodb.com/docs/atlas/configure-api-access/
    https://www.mongodb.com/docs/atlas/configure-api-access/#std-label-create-org-api-key
    Organization read only.
    """

    atlas_service: AtlasService
    db_user: str
    db_password: str
    writer: BaseWriter
    logger: Logger

    @classmethod
    def connect(
        cls,
        atlas_user: str,
        atlas_user_key: str,
        db_user: str,
        db_password: str,
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
        logger: Optional[Logger] = None,
    ):
        """Connect to the MongoDB atlas.
        Tries to authenticate with the provided credentials to the base API.
        Because Atlas is REST API, there is no notion of a connection.
        """
        writer = get_writer(filename=output_path, output_format=output_format)
        if logger is None:
            logger = get_logger(False)
        service = AtlasService.connect(atlas_user, atlas_user_key)
        return cls(atlas_service=service, writer=writer, logger=logger, db_user=db_user, db_password=db_password)

    def run(self):
        """Analyze authorization for a user and resource."""
        organizations = self.atlas_service.get_all_organizations()
        for organization in organizations:
            self._handle_organization(organization)

    def _handle_organization(self, organization: Organization):
        organization_users = self.atlas_service.get_all_organization_users_for_organization(organization)
        organization_teams = self.atlas_service.get_teams_for_organization(organization)
        
        for project in self.atlas_service.get_all_project_for_organization(organization):
            self._handle_project(organization, project, organization_users, organization_teams)
    
    def _handle_project(
        self,
        organization: Organization,
        project: Project,
        organization_users: set[OrganizationUser],
        organization_teams: Dict[str, OrganizationTeam],
    ):
        # path = [AuthzPathElement(id=project.id, name=project.name, type=AuthzPathElementType.PROJECT, note="")]
        
        for cluster in self.atlas_service.get_all_clusters_for_project(project):
            mongo_client: MongoClient[Any] = MongoClient(
                cluster.connection_string,
                username=self.db_user,
                password=self.db_password,
                tlsAllowInvalidCertificates=True,
                tls=True,
            )
            for db in mongo_client.list_database_names():
                db_connection = getattr(mongo_client, db)
                collections: List[
                    str
                ] = (
                    db_connection.list_collection_names()
                )
                for collection in collections:
                    asset = Asset(name= db + "." + collection, type=AssetType.COLLECTION)
                    self._report_organization_users(organization_users, asset=asset, organization=organization, project=project, cluster=cluster)
                    self._report_project_users(project, asset, path=path, organization_teams=organization_teams)
                    self._report_db_users(asset=asset, db=db, project=project, cluster=cluster)

    def _report_organization_users(self, organization_users: Set[OrganizationUser] , asset: Asset, organization: Organization, project: Project, cluster: Cluster):
        path = 
        for user in organization_users:
            identity = Identity(id=user.email_address, type=IdentityType.USER, name=user.username)
            for role in user.roles:
                permission_level = resolve_organization_role(role)
                if permission_level is not None:
                    role_entry = AuthzPathElement(id=role, name=role, type=AuthzPathElementType.ROLE, note=f"{user.username} has {role} role which grants {permission_level} on {asset.name}")
                    path.append(role_entry)
                    revered_path = list(reversed(path))
                    entry = AuthzEntry(identity=identity, asset=asset, permission=permission_level, path=revered_path)
                    self.writer.write_entry(entry)
                    path.pop()
    
    def _report_project_users(
        self,
        project: Project,
        asset: Asset,
        path: List[AuthzPathElement],
        organization_teams: Dict[str, OrganizationTeam],
    ):
        users = self.atlas_service.get_all_organization_users_for_project(project)
        project_teams_roles = self.atlas_service.get_teams_roles(project)
        for user in users:
            identity = Identity(id=user.email_address, type=IdentityType.USER, name=user.username)
            for role in user.roles:
                self._report_entry_project_user(identity, asset, role, path)
            for team_id in user.teams_ids:
                team_roles = project_teams_roles.get(team_id)
                if team_roles is not None:
                    org_team = organization_teams[team_id]
                    for role in team_roles:
                        team_path = AuthzPathElement(
                            id=team_id,
                            name=org_team.name,
                            type=AuthzPathElementType.TEAM,
                            note=f"{identity.name} is part of team {org_team.name}",
                        )
                        path.append(team_path)
                        self._report_entry_project_user(identity, asset, role, path)
                        path.pop()

    def _report_entry_project_user(
        self, identity: Identity, asset: Asset, role: OrganizationRoleName, path: List[AuthzPathElement]
    ):
        permission_level = resolve_project_role(role)
        if permission_level is not None:
            role_entry = AuthzPathElement(id=role, name=role, type=AuthzPathElementType.ROLE, note="")
            path.append(role_entry)
            revered_path = list(reversed(path))
            entry = AuthzEntry(identity=identity, asset=asset, permission=permission_level, path=revered_path)
            path.pop()
            self.writer.write_entry(entry)

    def _report_db_users(self, project: Project, asset: Asset, db: str, cluster: Cluster):
        db_users = self.atlas_service.get_all_db_users_for_project(project)
        for db_user in db_users:
            if len(db_user.scopes) != 0:
                db_user_scopes = {scope.name for scope in db_user.scopes}
                if cluster.name not in db_user_scopes:
                    continue
            identity = Identity(id=db_user.name, type=IdentityType.USER, name=db_user.name)
            for role in db_user.roles:
                self._report_entry_db_user(identity, asset, role, db)

    def _report_entry_db_user(self, identity: Identity, asset: Asset, role: DatabaseRole, db: str):
        role_map = resolve_database_role(role.name)
        if role_map is not None:
            permission_level, scope = role_map
            path = [AuthzPathElement(id=role.name, name=role.name, type=AuthzPathElementType.ROLE, note="")]
            entry = AuthzEntry(identity=identity, asset=asset, permission=permission_level, path=path)
            if scope == PermissionScope.PROJECT:
                self.writer.write_entry(entry)
            elif scope == PermissionScope.DATABASE and role.database_name == db:
                self.writer.write_entry(entry)
            elif scope == PermissionScope.COLLECTION:
                if role.collection is None:  # In this case the role applies to all collections in the database
                    self.writer.write_entry(entry)
                elif role.collection == asset.name:
                    self.writer.write_entry(entry)
