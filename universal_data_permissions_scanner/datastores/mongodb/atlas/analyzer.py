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
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

from universal_data_permissions_scanner.datastores.mongodb.atlas.model import (
    Action,
    Cluster,
    CustomRole,
    DatabaseRole,
    Organization,
    OrganizationRoleName,
    OrganizationUser,
    Project,
)
from universal_data_permissions_scanner.datastores.mongodb.atlas.permission_resolvers import (
    PermissionScope,
    resolve_database_role,
    resolve_organization_role,
    resolve_permission,
    resolve_project_role,
)
from universal_data_permissions_scanner.datastores.mongodb.atlas.service import AtlasService
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
from universal_data_permissions_scanner.utils.logger import get_logger
from universal_data_permissions_scanner.writers import BaseWriter, OutputFormat
from universal_data_permissions_scanner.writers.base_writers import DEFAULT_OUTPUT_FILE
from universal_data_permissions_scanner.writers.get_writers import get_writer

PermissionOrganizationUserMap = Dict[PermissionLevel, Set[OrganizationUser]]


@dataclass
class MongoDBAtlasAuthzAnalyzer:
    """Analyze authorization for Atlas MongoDB.
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
    project_name: str
    cluster_name: str

    @classmethod
    def connect(
        cls,
        public_key: str,
        private_key: str,
        db_user: str,
        db_password: str,
        project_name: str,
        cluster_name: str,
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
        logger: Optional[Logger] = None,
    ):
        """Connect to the MongoDB atlas.
        Tries to authenticate with the provided credentials to the base API.
        Because Atlas is REST API, there is no notion of a connection.
        """
        if logger is None:
            logger = get_logger(False)
        logger.info("Starting to scan project %s, cluster %s", project_name, cluster_name)

        writer = get_writer(filename=output_path, output_format=output_format)

        service = AtlasService.connect(public_key, private_key)
        return cls(
            atlas_service=service,
            writer=writer,
            logger=logger,
            db_user=db_user,
            db_password=db_password,
            project_name=project_name,
            cluster_name=cluster_name,
        )

    def run(self):
        """Analyze authorization for a user and resource."""
        project_info = self.atlas_service.get_project_info_by_project_name(self.project_name)
        organization_info = self.atlas_service.get_organization_info_by_id(project_info["orgId"])

        organization = Organization.new(project_info["orgId"], organization_info["name"])
        organization.users = self.atlas_service.get_all_organization_users_for_organization(organization)
        organization.teams = self.atlas_service.get_teams_for_organization(organization)

        project = Project(name=self.project_name, id=project_info["id"])

        self._handle_project(organization, project)

    def _handle_project(
        self,
        organization: Organization,
        project: Project,
    ):
        cluster_info = self.atlas_service.get_cluster_info_by_name(project.id, self.cluster_name)
        connection_string = cluster_info["connectionStrings"]["standardSrv"].split(',')[0]
        cluster = Cluster(name=cluster_info["name"], id=cluster_info["id"], connection_string=connection_string)
        mongo_client = self.atlas_service.get_mongodb_client(cluster.connection_string, self.db_user, self.db_password)
        for db_name, db_connection in mongo_client.iter_database_connections():
            for collection in db_connection.list_collection_names():
                asset = Asset(name=[db_name, collection], type=AssetType.COLLECTION)
                self._report_organization_users(
                    asset=asset, organization=organization, project=project, cluster=cluster, db=db_name
                )
                self._report_project_users(project, asset, db=db_name, organization=organization, cluster=cluster)
                self._report_db_users(asset=asset, db=db_name, project=project, cluster=cluster)

    def _report_organization_users(
        self,
        asset: Asset,
        organization: Organization,
        project: Project,
        cluster: Cluster,
        db: str,  # pylint: disable=invalid-name
    ):
        path = [
            AuthzPathElement(
                id=project.id,
                name=project.name,
                type=AuthzPathElementType.PROJECT,
                notes=[AuthzNote.to_generic_note(f"cluster {cluster.name} is part of project {project.name}")],
            ),
            AuthzPathElement(
                id=cluster.name,
                name=cluster.name,
                type=AuthzPathElementType.CLUSTER,
                notes=[AuthzNote.to_generic_note(f"database {db} is part of cluster {cluster.name}")],
            ),
        ]
        for user in organization.users:
            identity = Identity(id=user.email_address, type=IdentityType.ORG_USER, name=user.username)
            path.insert(
                0,
                AuthzPathElement(
                    id=organization.id,
                    name=organization.name,
                    type=AuthzPathElementType.ORGANIZATION,
                    notes=[
                        AuthzNote.to_generic_note(
                            f"Organization user {user.username} is part of organization {organization.name}"
                        )
                    ],
                ),
            )
            for role in user.roles:
                permission_level = resolve_organization_role(role)
                if permission_level is not None:
                    collection_name = ".".join(asset.name)
                    role_entry = AuthzPathElement(
                        id=role,
                        name=role,
                        type=AuthzPathElementType.ROLE,
                        notes=[
                            AuthzNote.to_generic_note(
                                f"{user.username} has {role} role which grants {permission_level} access on {collection_name}"
                            )
                        ],
                    )
                    path.insert(0, role_entry)
                    entry = AuthzEntry(identity=identity, asset=asset, permission=permission_level, path=path)
                    self.writer.write_entry(entry)
                    path.pop(0)
            path.pop(0)

    def _report_project_users(  # pylint: disable=too-many-locals
        self,
        project: Project,
        asset: Asset,
        cluster: Cluster,
        db: str,  # pylint: disable=invalid-name
        organization: Organization,
    ):
        path = [
            AuthzPathElement(
                id=cluster.name,
                name=cluster.name,
                type=AuthzPathElementType.CLUSTER,
                notes=[AuthzNote.to_generic_note(f"database {db} is part of cluster {cluster.name}")],
            ),
        ]
        users = self.atlas_service.get_all_organization_users_for_project(project)
        project_teams_roles = self.atlas_service.get_teams_roles(project)
        for user in users:
            identity = Identity(id=user.email_address, type=IdentityType.ORG_USER, name=user.username)
            for role in user.roles:
                path.insert(
                    0,
                    AuthzPathElement(
                        id=project.id,
                        name=project.name,
                        type=AuthzPathElementType.PROJECT,
                        notes=[
                            AuthzNote.to_generic_note(f"User {user.username} has {role} role defined at {project.name}")
                        ],
                    ),
                )
                self._report_entry_project_user(identity, asset, role, path)
                path.pop(0)
            for org_user in organization.users:
                identity = Identity(id=org_user.email_address, type=IdentityType.ORG_USER, name=org_user.username)
                for team_id in org_user.teams_ids:
                    team_roles = project_teams_roles.get(team_id)
                    if team_roles is not None:
                        org_team = organization.teams[team_id]
                        for role in team_roles:
                            team_path = AuthzPathElement(
                                id=team_id,
                                name=org_team.name,
                                type=AuthzPathElementType.TEAM,
                                notes=[AuthzNote.to_generic_note(f"{identity.name} is part of team {org_team.name}")],
                            )
                            path.append(team_path)
                            self._report_entry_project_user(identity, asset, role, path)
                            path.pop()

    def _report_entry_project_user(
        self, identity: Identity, asset: Asset, role: OrganizationRoleName, path: List[AuthzPathElement]
    ):
        permission_level = resolve_project_role(role)
        if permission_level is not None:
            collection_name = ".".join(asset.name)
            role_entry = AuthzPathElement(
                id=role,
                name=role,
                type=AuthzPathElementType.ROLE,
                notes=[
                    AuthzNote.to_generic_note(
                        f"User {identity.name} has {role} role which grants {permission_level} access on {collection_name}"
                    )
                ],
            )
            path.insert(0, role_entry)
            entry = AuthzEntry(identity=identity, asset=asset, permission=permission_level, path=path)
            self.writer.write_entry(entry)
            path.pop(0)

    def _report_db_users(
        self, project: Project, asset: Asset, db: str, cluster: Cluster
    ):  # pylint: disable=invalid-name
        db_users = self.atlas_service.get_all_db_users_for_project(project)
        project_custom_roles = self.atlas_service.get_custom_roles_by_project(project)
        for db_user in db_users:
            if len(db_user.scopes) != 0:
                db_user_scopes = {scope.name for scope in db_user.scopes}
                if cluster.name not in db_user_scopes:
                    continue
            identity = Identity(id=db_user.name, type=IdentityType.DB_USER, name=db_user.name)
            for role in db_user.roles:
                self._report_entry_db_user(identity, asset, role, db, project_custom_roles)

    def _report_entry_db_user(  # pylint: disable=too-many-branches
        self,
        identity: Identity,
        asset: Asset,
        role: DatabaseRole,
        db: str,  # pylint: disable=invalid-name
        project_custom_roles: Dict[str, CustomRole],
    ):
        role_map = resolve_database_role(role.name)

        if role_map is not None:
            permission_level, scope = role_map
            path = [
                AuthzPathElement(
                    id=role.name,
                    name=role.name,
                    type=AuthzPathElementType.ROLE,
                    notes=[
                        AuthzNote.to_generic_note(
                            f"DB user {identity.name} has {role.name} role which grants {permission_level} access on {asset.name}"
                        )
                    ],
                )
            ]
            entry = AuthzEntry(identity=identity, asset=asset, permission=permission_level, path=path)
            if scope == PermissionScope.PROJECT:
                self.writer.write_entry(entry)
            elif scope == PermissionScope.DATABASE and role.database_name == db:
                self.writer.write_entry(entry)
            elif scope == PermissionScope.COLLECTION:
                if role.collection is None:  # In this case the role applies to all collections in the database
                    self.writer.write_entry(entry)
                elif role.collection == asset.name[1]:
                    self.writer.write_entry(entry)
        else:
            custom_role = project_custom_roles.get(role.name)
            if custom_role is not None:
                for inherited_role in custom_role.inherited_roles:
                    role_map = resolve_database_role(inherited_role.name)
                    if role_map is not None:
                        permission_level, scope = role_map
                        collection_name = ".".join(asset.name)
                        path = [
                            AuthzPathElement(
                                id=custom_role.name,
                                name=custom_role.name,
                                type=AuthzPathElementType.ROLE,
                                notes=[
                                    AuthzNote.to_generic_note(
                                        f"DB user {identity.name} has {custom_role.name} role which grants {permission_level} access on {collection_name}"
                                    )
                                ],
                            )
                        ]
                        entry = AuthzEntry(identity=identity, asset=asset, permission=permission_level, path=path)
                        if scope == PermissionScope.PROJECT:
                            self.writer.write_entry(entry)
                        elif scope == PermissionScope.DATABASE and inherited_role.database == db:
                            self.writer.write_entry(entry)
                collection_name = ".".join(asset.name)
                permission_level = MongoDBAtlasAuthzAnalyzer._get_highest_permission(
                    custom_role.actions, collection_name
                )
                if permission_level is not None:
                    role_db_permissions = [str(action.permission) for action in custom_role.actions]
                    path = [
                        AuthzPathElement(
                            id=custom_role.name,
                            name=custom_role.name,
                            type=AuthzPathElementType.ROLE,
                            notes=[
                                AuthzNote.to_generic_note(
                                    f"DB user {identity.name} has {custom_role.name} role which grants {permission_level} access on {collection_name}"
                                )
                            ],
                            db_permissions=role_db_permissions,
                        )
                    ]
                    entry = AuthzEntry(identity=identity, asset=asset, permission=permission_level, path=path)
                    self.writer.write_entry(entry)

    @staticmethod
    def _get_highest_permission(actions: Set[Action], collection: str):
        highest_permission_level: Optional[PermissionLevel] = None
        for action in actions:
            if action.resource.collection in ("", collection):
                permission = resolve_permission(action.permission)
                if permission is not None:
                    if highest_permission_level is None or permission > highest_permission_level:  # type: ignore
                        highest_permission_level = permission
        return highest_permission_level
