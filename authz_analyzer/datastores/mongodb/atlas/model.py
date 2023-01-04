"""Translate the MongoDB Atlas API to the model used by the analyzer."""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Set

from authz_analyzer.datastores.mongodb.atlas.service_model import (
    ClusterEntry,
    DataBaseUserEntry,
    OrganizationTeamEntry,
    OrganizationUserEntry,
)


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
        return hash(self.name) + hash(self.database_name)


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

        return cls(
            id=entry["id"],
            email_address=entry["emailAddress"],
            username=entry["username"],
            roles=roles,
            teams_ids=teams_ids,
        )


@dataclass
class OrganizationTeam:
    """Define an Atlas team."""

    id: OrganizationTeamId
    name: str

    def __hash__(self) -> int:
        return hash(self.id)

    @classmethod
    def build_from_response(cls, entry: OrganizationTeamEntry):
        """Build a database user from the response."""
        return cls(id=entry["id"], name=entry["name"])


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
