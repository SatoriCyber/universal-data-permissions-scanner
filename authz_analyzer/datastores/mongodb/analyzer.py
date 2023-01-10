"""Analyze authorization for MongoDB.

Database users:
Users are defined in the project level.
Type of users:
    Local users - users who are defined in the Atlas.
    LDAP users - users who are defined in the LDAP.
    X.509 users - users who are defined in the X.509.
Roles have scope:
    Database - All databases in the cluster
    Collection - All collections in the database.
"""
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from pymongo import MongoClient

from authz_analyzer.datastores.mongodb.atlas.model import OrganizationUser
from authz_analyzer.datastores.mongodb.model import AdminRole, AdminUser, Privilege, Role
from authz_analyzer.datastores.mongodb.resolvers import (
    get_permission_level,
    get_permission_level_cluster,
    get_permission_level_privilege,
)
from authz_analyzer.datastores.mongodb.service import MongoDBService
from authz_analyzer.datastores.mongodb.service_model import AssignedRole, UserEntry
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
from authz_analyzer.writers import BaseWriter, OutputFormat
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

    client: MongoDBService
    writer: BaseWriter
    logger: Logger

    @classmethod
    def connect(
        cls,
        host: str,
        username: str,
        password: str,
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
        logger: Optional[Logger] = None,
        **kwargs: Any,
    ):
        """Connect to MongoDB.

        Args:
            host (str): hostname of the mongodb server
            username (str): username
            password (str): password
            output_format (OutputFormat, optional): Output format. Defaults to OutputFormat.CSV.
            output_path (Union[Path, str], optional): Output path. Defaults to Path.cwd()/DEFAULT_OUTPUT_FILE.
            logger (Optional[Logger], optional): Logger. Defaults to None.

        Raises:
            ConnectionError: Unable to connect

        Returns:
            MongoDBAuthzAnalyzer: Analyzer
        """
        writer = get_writer(filename=output_path, output_format=output_format)
        try:
            client = MongoDBService(MongoClient(
                    host,
                    username=username,
                    password=password,
                    tlsAllowInvalidCertificates=True,
                    tls=True,
                    **kwargs,
                ))
        except Exception as err:
            raise ConnectionError(
                f"Could not connect to {host} with the provided credentials"
            ) from err
        if logger is None:
            logger = get_logger(False)
        return cls(writer=writer, logger=logger, client=client)

    def run(self):
        """Analyze authorization for a user and resource."""
        admin_users = self._handle_admin_users()
        for (database_name, db_connection) in self.client.iter_database_connections():
            if database_name == "admin": # Because admin database is special case, we need to handle it separately.
                continue
            users = self.client.get_users(db_connection)
            collections = db_connection.list_collection_names()
            custom_roles = self.client.get_custom_roles(db_connection)
            self._report_users(database_name=database_name, users=users, collections=collections, admin_users=admin_users, custom_roles=custom_roles)
    
    def _handle_admin_users(self) -> Set[AdminUser]:
        """Get admin users."""
        admin_db = self.client.client["admin"]
        admin_users = self.client.get_users(admin_db)
        custom_roles = self.client.get_custom_roles(admin_db)
        fileted_admin_users: Set[AdminUser] = set()
        for user in admin_users:
            for role in user['roles']:
                relevant_admin_user = MongoDBAuthzAnalyzer._get_admin_user_by_permission(user, role)
                if relevant_admin_user is not None:
                    fileted_admin_users.add(relevant_admin_user)
        collection = admin_db.list_collection_names()
        self._report_users(database_name="admin", users=admin_users, collections=collection, admin_users=fileted_admin_users, custom_roles=custom_roles)
        
        return fileted_admin_users
    
    @staticmethod
    def _get_admin_user_by_permission(user: UserEntry, role: AssignedRole) -> Optional[AdminUser]:
        permission_level = get_permission_level_cluster(role['role'])
        if permission_level is not None:
            return (AdminUser(id=user["user"], name=user["user"], role=AdminRole(name=role['role'], permission_level=permission_level)))
        return None

    def _report_users(self, database_name: str, users: List[UserEntry], collections: List[str], admin_users: Set[AdminUser], custom_roles: Dict[str, Role]):
        for collection in collections:
            asset = Asset(type=AssetType.COLLECTION, name=database_name + "." + collection)
            for user in users:
                self._report_user(user=user, asset=asset, custom_roles=custom_roles, collection=collection)
            for admin_user in admin_users:
                self._report_admin_user(user=admin_user, asset=asset)
    
    def _report_user(self, user: UserEntry,  asset: Asset, custom_roles: Dict[str, Role], collection: str):
        for role in user['roles']:
            custom_role = custom_roles.get(role['role'])
            if custom_role is not None:
                # Handle custom roles privileges
                self._handle_custom_role_privileges(custom_role, user=user, asset=asset, collection=collection, custom_roles=custom_roles, path=[])
            permission = get_permission_level(role['role'])
            if permission is not None:
                path = [AuthzPathElement(type=AuthzPathElementType.ROLE, name=role['role'], id=role['role'], note=f"{user['user']} has {role['role']} role which gives {permission} permission on {collection}")]
                self._write_entry(user_id=user["user"], username=user["user"], asset=asset, permission=permission, path=path)

    def _handle_custom_role_privileges(self, custom_role: Role, user: UserEntry, asset: Asset, collection: str, custom_roles: Dict[str, Role], path: List[AuthzPathElement]):
        path.append(AuthzPathElement(type=AuthzPathElementType.ROLE, name=custom_role.name, id=custom_role.name, note=""))
        highest_permission_level: Optional[PermissionLevel] = None
        for inherited_role in custom_role.inherited_roles:
            role = custom_roles.get(inherited_role.name)
            if role is None:
                permission = get_permission_level(inherited_role.name) #handle built-in roles
                if permission is not None:
                    path.append(AuthzPathElement(type=AuthzPathElementType.ROLE, name=inherited_role.name, id=inherited_role.name, note=""))
                    self._write_entry(user_id=user["user"], username=user["user"], asset=asset, permission=permission, path=path)
                    path.pop()
            else:
                self._handle_custom_role_privileges(role, user=user, asset=asset, collection=collection, custom_roles=custom_roles, path=path)

        for privilege in custom_role.privileges:
            highest_permission_level = MongoDBAuthzAnalyzer._get_highest_permission(privilege, collection)
            if highest_permission_level is not None:
                self._write_entry(user_id=user["user"], username=user["user"], asset=asset, permission=highest_permission_level, path=path)
        path.pop()
                


    @staticmethod
    def _get_highest_permission(privilege: Privilege, collection: str):
        highest_permission_level: Optional[PermissionLevel] = None
        if privilege.resource.collection in ("", collection):
            for action in privilege.actions:
                permission = get_permission_level_privilege(action)
                if permission is not None:
                    if highest_permission_level is None or permission > highest_permission_level: #type: ignore
                        highest_permission_level = permission
        return highest_permission_level
    
    def _report_admin_user(self, user: AdminUser, asset: Asset):
        authz_path = [AuthzPathElement(id=user.role.name, type=AuthzPathElementType.ROLE, name=user.role.name, note=f"{user.name} has role {user.role.name} which grants {user.role.permission_level} permission")]
        self._write_entry(user_id=user.id, username=user.name, asset=asset, permission=user.role.permission_level, path = authz_path)

    def _write_entry(self, user_id: str, username: str, asset: Asset, permission: PermissionLevel, path: List[AuthzPathElement]):
        identity = Identity(id=user_id, type=IdentityType.USER, name=username)
        self.writer.write_entry(
            AuthzEntry(
                identity=identity,
                asset=asset,
                permission=permission,
                path=path,
            )
        )
