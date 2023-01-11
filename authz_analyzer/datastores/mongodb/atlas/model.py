"""Translate the MongoDB Atlas API to the model used by the analyzer."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Optional, Set

from authz_analyzer.datastores.mongodb.atlas.service_model import (
    ClusterEntry,
    CustomRoleEntry,
    DataBaseUserEntry,
    OrganizationTeamEntry,
    OrganizationUserEntry,
)
from authz_analyzer.datastores.mongodb.model import InheritedRole, Resource

OrganizationRoleName = str
OrganizationTeamId = str


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


@dataclass
class OrganizationRole:
    """Define an Atlas organization role."""

    id: str
    name: str

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class Organization:
    """MongoDB organization."""

    name: str
    id: str
    users: Set[OrganizationUser]
    teams: Dict[OrganizationTeamId, OrganizationTeam]

    @classmethod
    def new(cls, name: str, org_id: str):
        return cls(name, org_id, set(), {})

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


@dataclass
class DatabaseRole:
    """Database role, Used by MongoDB."""

    name: str
    database_name: str
    collection: Optional[str]

    def __hash__(self) -> int:
        return hash(self.name) + hash(self.database_name)


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


class Permission(Enum):
    """Permission allowed by a role."""

    FIND = auto()
    INSERT = auto()
    REMOVE = auto()
    UPDATE = auto()
    DROP_COLLECTION = auto()
    DROP_DATABASE = auto()
    RENAME_COLLECTION_SAME_DB = auto()
    LIST_COLLECTIONS = auto()
    SQL_GET_SCHEMA = auto()
    SQL_SET_SCHEMA = auto()
    OUT_TO_S3 = auto()


@dataclass
class Action:
    """List of resources and the permission granted on them"""

    resource: Resource
    permission: Permission

    def __hash__(self) -> int:
        return hash(self.resource) + hash(self.permission)


@dataclass
class CustomRole:
    """Define a custom role."""

    name: str
    action: Optional[Action]
    inherited_role: Optional[InheritedRole]

    def __hash__(self) -> int:
        return hash(self.name)

    @staticmethod
    def build_custom_roles_from_response(entry: CustomRoleEntry) -> Set[CustomRole]:
        """Build set of custom roles from the response.

        Instead of having a single custom roles with all the action and inherited roles, we split them into multiple custom roles.
        """
        custom_roles: Set[CustomRole] = set()
        for action in entry["actions"]:
            try:
                permission = Permission[action["action"]]
            except KeyError:  # ignore actions that doesn't access data, we don't need them
                continue
            for resource in action["resources"]:
                resolved_resource = Resource(collection=resource["collection"], database=resource["db"])
                custom_roles.add(
                    CustomRole(
                        name=entry["roleName"],
                        action=Action(resource=resolved_resource, permission=permission),
                        inherited_role=None,
                    )
                )

        for inherited_role in entry["inheritedRoles"]:
            custom_roles.add(
                CustomRole(
                    name=entry["roleName"],
                    action=None,
                    inherited_role=InheritedRole(database=inherited_role["db"], name=inherited_role["role"]),
                )
            )

        return custom_roles
