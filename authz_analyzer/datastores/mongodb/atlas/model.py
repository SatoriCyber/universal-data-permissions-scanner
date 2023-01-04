"""Translate the MongoDB Atlas API to the model used by the analyzer."""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Set

from authz_analyzer.datastores.mongodb.atlas.service_model import ClusterEntry, DataBaseUserEntry, OrganizationUserEntry, ProjectTeamEntry
from authz_analyzer.models.model import PermissionLevel


class PermissionScope(Enum):
    """Define the scope of the permission."""

    COLLECTION = auto()
    PROJECT = auto()
    DATABASE = auto()


BUILT_IN_ROLE_MAPPING_ORGANIZATION = {
    "ORG_OWNER": PermissionLevel.FULL,
    "ORG_READ_ONLY": PermissionLevel.READ,
}

BUILT_IN_ROLE_MAPPING_PROJECT = {
    "GROUP_OWNER": PermissionLevel.FULL,
    "GROUP_DATA_ACCESS_ADMIN": PermissionLevel.FULL,
    "GROUP_DATA_ACCESS_READ_WRITE": PermissionLevel.FULL,
    "GROUP_DATA_ACCESS_READ_ONLY": PermissionLevel.READ,
}


BUILT_IN_ROLE_MAPPING = {
    "atlasAdmin": (PermissionLevel.FULL, PermissionScope.PROJECT),
    "readWriteAnyDatabase": (PermissionLevel.FULL, PermissionScope.PROJECT),
    "readAnyDatabase": (PermissionLevel.READ, PermissionScope.PROJECT),
    "dbAdmin": (PermissionLevel.FULL, PermissionScope.DATABASE),
    "dbAdminAnyDatabase": (PermissionLevel.FULL, PermissionScope.PROJECT),
    "read": (PermissionLevel.READ, PermissionScope.COLLECTION),
    "readWrite": (PermissionLevel.WRITE, PermissionScope.COLLECTION),

}

PRIVILEGE_MAPPING = {
    "find": PermissionLevel.READ,
    "insert": PermissionLevel.WRITE,
    "remove": PermissionLevel.WRITE,
    "update": PermissionLevel.WRITE,
    "changeStream": PermissionLevel.READ,
    "dropCollection": PermissionLevel.WRITE,
    "dropDatabase": PermissionLevel.WRITE,
    "listCollections": PermissionLevel.READ,
    "listIndexes": PermissionLevel.READ,
    "listDatabases": PermissionLevel.READ,
    "anyAction": PermissionLevel.FULL,
}


@dataclass
class Organization:
    """MongoDB organization."""

    name: str
    id: str

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class Project:
    """Single MongoDB project."""

    id: str
    name: str

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class Cluster:
    """Single MongoDB cluster."""

    id: str
    name: str
    connection_string: str

    def __hash__(self) -> int:
        return hash(self.id)

    @classmethod
    def build_from_response(cls, response: ClusterEntry):
        """Build cluster from response."""
        # The connection string is built from two parts, we need only the first one.
        connection_string = response["connectionStrings"]["standardSrv"].split(',')[0]
        return Cluster(id=response["id"], connection_string=connection_string, name=response["name"])



OrganizationRoleName = str
OrganizationTeamId = str

@dataclass
class DatabaseRole:
    """Database role, used by MongoDB and not Atlas."""
    name: str
    database_name: str
    collection: Optional[str]

    def __hash__(self) -> int:
        return hash(self.name) + hash (self.database_name)
    
    def get_permission_level_and_scope(self):
        """Get the permission level of the role."""
        return BUILT_IN_ROLE_MAPPING.get(self.name, None)

@dataclass
class OrganizationRole:
    """Define an Atlas organization role."""
    id: str
    name: str

    def __hash__(self) -> int:
        return hash(self.id)




@dataclass
class OrganizationUser:
    """Define an Atlas organization user."""
    id: str
    email_address: str
    username: str
    teams_ids: Set[OrganizationTeamId]
    roles: Set[OrganizationRoleName]

    def __hash__(self) -> int:
        return hash(self.id)

    @classmethod
    def build_from_response(cls, entry: OrganizationUserEntry):
        """Build a database user from the response."""
        roles: Set[OrganizationRoleName] = {role["roleName"] for role in entry["roles"]}
        teams_ids: Set[OrganizationTeamId] = set(entry['teamIds'])

        return cls(id = entry["id"], email_address = entry["emailAddress"], username=entry["username"], roles=roles, teams_ids=teams_ids)


@dataclass
class ProjectTeam:
    """Define an Atlas team."""
    id: OrganizationTeamId
    roles: Set[OrganizationRoleName]

    def __hash__(self) -> int:
        return hash(self.id)

    @classmethod
    def build_from_response(cls, entry: ProjectTeamEntry):
        """Build a database user from the response."""
        roles: Set[OrganizationRoleName] = set(entry['roleNames'])

        return cls(id = entry["teamId"], roles=roles)         


@dataclass
class OrganizationTeam:
    """Define an Atlas team."""
    id: OrganizationTeamId
    name: str
    # roles: Set[OrganizationRoleName]

    def __hash__(self) -> int:
        return hash(self.id)
        

class DatabaseUserScopeType(Enum):
    CLUSTER = auto()

@dataclass
class DatabaseUserScope:
    name: str
    type: DatabaseUserScopeType

    def __hash__(self) -> int:
        return hash(self.name) + hash(self.type)

@dataclass
class DatabaseUser:
    """Define a database user."""
    name: str
    roles: Set[DatabaseRole]
    scopes: Set[DatabaseUserScope]

    def __hash__(self) -> int:
        return hash(self.name)
    
    @classmethod
    def build_from_response(cls, entry: DataBaseUserEntry):
        """Build a database user from the response."""
        roles: Set[DatabaseRole] = set()
        scopes: Set[DatabaseUserScope] = set()
        for scope in entry["scopes"]:
            if scope["type"] == "CLUSTER":
                scopes.add(DatabaseUserScope(scope["name"], DatabaseUserScopeType.CLUSTER))
        for role in entry["roles"]:
            collection_name = role.get("collectionName")
            roles.add(DatabaseRole(role["roleName"], role["databaseName"], collection_name))
        return cls(entry["username"], roles, scopes)
