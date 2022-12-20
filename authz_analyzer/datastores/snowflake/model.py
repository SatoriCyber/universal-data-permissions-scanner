from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set

from authz_analyzer.models import PermissionLevel


PERMISSION_LEVEL_MAP = {
    "SELECT": PermissionLevel.READ,
    "REFERENCES": PermissionLevel.READ,
    "INSERT": PermissionLevel.WRITE,
    "UPDATE": PermissionLevel.WRITE,
    "DELETE": PermissionLevel.WRITE,
    "TRUNCATE": PermissionLevel.WRITE,
    "REBUILD": PermissionLevel.WRITE,
    "OWNERSHIP": PermissionLevel.FULL,
}

@dataclass
class User:
    name: str
    id: str

    def __hash__(self) -> int:
        return hash(self.id)


RoleName = str
Username = User


@dataclass
class ResourceGrant:
    """Define a resource, e.g. a table, and the permission level."""
    name: str
    permission_level: PermissionLevel

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class DBRole:
    """Define a role which grants access from a user to a resource."""
    name: str
    roles: Set[DBRole]

    @classmethod
    def new(cls, name: str, roles: Set[DBRole]):
        """Creates a new DBRole."""
        return cls(name=name, roles=roles)

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class AuthorizationModel:
    """Define the authorization model.
    User to roles -> map a user to the roles it has
    Role to roles -> map a role to the roles it has
    Role to grants -> map a role to the grants it has
    """
    users_to_roles: Dict[Username, Set[DBRole]]
    role_to_roles: Dict[RoleName, Set[DBRole]]
    roles_to_grants: Dict[RoleName, Set[ResourceGrant]]
