"""Analyze authorization for MongoDB.

MongoDB implements RBAC.
User have roles.
A role grants privileges to a resource.
Role can inherit from other roles.
A privilege consists of a specified resource and the actions permitted on the resource.

A resource is a database, collection, set of collections, or the cluster

A role can inherit privileges from other roles in its database. 
A role created on the admin database can inherit privileges from roles in any database.

View Role's Privileges
You can view the privileges for a role by issuing the rolesInfo command with the showPrivileges and showBuiltinRoles fields both set to true.

For a user-defined role scoped for a non-admin database, the resource specification for its privileges must specify the same database as the role. 
User-defined roles scoped for the admin database can specify other databases.

If only the collection field is an empty string (""), the resource is the specified database, excluding the system collections.

When you specify a database as the resource, system collections are excluded, unless you name them explicitly

If only the db field is an empty string (""), the resource is all collections with the specified name across all databases.
For user-defined roles, only roles scoped for the admin database can have this resource specification for their privileges
If both the db and collection fields are empty strings (""), the resource is all collections, excluding the system collections,

To specify the cluster as the resource, use the following syntax:

{ cluster : true }

The internal resource anyResource gives access to every resource in the system and is intended for internal use. 
Do not use this resource, other than in exceptional circumstances. 
The syntax for this resource is { anyResource: true }.

MongoDB provides the built-in database user and database administration roles on every database.
MongoDB provides all other built-in roles only on the admin database.



Strategy:
1. Get all organizations
2. analyze each organization
3. Get all users and teams for organization
4. Get all custom roles for organization
5. Get all projects for organization
"""
from logging import Logger
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Union

from pymongo import MongoClient


from authz_analyzer.datastores.mongodb.atlas.service import AtlasService
from authz_analyzer.datastores.mongodb.atlas.model import Cluster, Organization, PermissionScope, Project
from authz_analyzer.datastores.mongodb.atlas.model import BUILT_IN_ROLE_MAPPING_PROJECT, OrganizationRoleName, OrganizationTeam, OrganizationUser, BUILT_IN_ROLE_MAPPING, DatabaseRole
from authz_analyzer.models.model import Asset, AssetType, AuthzEntry, AuthzPathElement, AuthzPathElementType, Identity, IdentityType
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import OutputFormat, BaseWriter
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE
from authz_analyzer.writers.get_writers import get_writer


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
    def connect(cls, atlas_user: str, atlas_user_key: str, db_user:str, db_password: str, output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE, logger: Optional[Logger] = None):
        """Connect to the MongoDB atlas.
        Tries to authenticate with the provided credentials to the base API.
        Because Atlas is REST API, there is no notion of a connection.
        """
        writer = get_writer(filename=output_path, output_format=output_format)
        if logger is None:
            logger = get_logger(False)     
        service = AtlasService.connect(atlas_user, atlas_user_key)
        return cls(
            atlas_service=service, 
            writer=writer, 
            logger=logger, 
            db_user=db_user, 
            db_password=db_password
            )
    
    def run(self):
        """Analyze authorization for a user and resource."""
        organizations = self.atlas_service.get_all_organizations()
        for organization in organizations:
            self._handle_organization(organization)


    def _handle_organization(self, organization: Organization):
        organization_users = self.atlas_service.get_all_organization_users_for_organization(organization)
        organization_teams = self.atlas_service.get_all_organization_teams_for_organization(organization)
        projects = self.atlas_service.get_all_project_for_organization(organization)
        for project in projects:
            self._handle_project(project, organization_users, organization_teams)
    
    
    
    def _handle_project(self, project: Project, organization_users: Set[OrganizationUser], organization_teams: Dict[str, OrganizationTeam]):
        clusters = self.atlas_service.get_all_clusters_for_project(project)
        path = [AuthzPathElement(id=project.id, name=project.name, type=AuthzPathElementType.PROJECT, note="")]

        for cluster in clusters:
            mongo_client: MongoClient[Any] = MongoClient(cluster.connection_string, username=self.db_user, password=self.db_password, tlsAllowInvalidCertificates=True, tls=True)
            for db in mongo_client.list_database_names():
                db_connection = getattr(mongo_client, db)
                collections: List[str] = db_connection.list_collection_names() # Now I got the list of collection per org.cluster.db.collections, need to start going over the data lazily
                for collection in collections:
                    asset = Asset(name=cluster.name + "." + db + "." + collection, type=AssetType.COLLECTION)
                    self._report_project_users(project, asset, path=path, organization_teams=organization_teams)
                    self._report_db_users(asset=asset, db=db, project=project, cluster=cluster)


    def _report_project_users(self, project: Project, asset: Asset, path: List[AuthzPathElement], organization_teams: Dict[str, OrganizationTeam]):
        users = self.atlas_service.get_all_organization_users_for_project(project)
        teams = self.atlas_service.get_all_organization_teams_for_project(project)
        for user in users:
            identity = Identity(id=user.email_address, type=IdentityType.USER, name=user.username)
            for role in user.roles:
                self._report_entry_project_user(identity, asset, role, path)
            for team_id in user.teams_ids:
                user_team = teams.get(team_id)
                if user_team is not None:
                    org_team = organization_teams[team_id]
                    for role in user_team.roles:
                        team_path = AuthzPathElement(id = team_id, name=org_team.name, type=AuthzPathElementType.TEAM, note=f"{identity.name} is part of team {org_team.name}")
                        path.append(team_path)
                        self._report_entry_project_user(identity, asset, role, path)
                        path.pop()
            
    def _report_entry_project_user(self, identity: Identity, asset: Asset, role: OrganizationRoleName, path: List[AuthzPathElement]):
        permission_level = BUILT_IN_ROLE_MAPPING_PROJECT.get(role)
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
                db_user_scopes = { scope.name for scope in db_user.scopes }
                if cluster.name not in db_user_scopes:
                    continue
            identity = Identity(id=db_user.name, type=IdentityType.USER, name=db_user.name)
            for role in db_user.roles:
                self._report_entry_db_user(identity, asset, role, db)
        

    def _report_entry_db_user(self, identity: Identity, asset: Asset, role: DatabaseRole, db: str):
        role_map = BUILT_IN_ROLE_MAPPING.get(role.name)
        if role_map is not None:
            permission_level, scope = role_map
            path = [AuthzPathElement(id=role.name, name=role.name, type=AuthzPathElementType.ROLE, note="")]
            entry = AuthzEntry(identity=identity, asset=asset, permission=permission_level, path=path)
            if scope == PermissionScope.PROJECT:
                self.writer.write_entry(entry)
            elif scope == PermissionScope.DATABASE and role.database_name == db:
                self.writer.write_entry(entry)
            elif scope == PermissionScope.COLLECTION:
                if role.collection is None: # In this case the role applies to all collections in the database
                    self.writer.write_entry(entry)
                elif role.collection == asset.name:
                    self.writer.write_entry(entry)
