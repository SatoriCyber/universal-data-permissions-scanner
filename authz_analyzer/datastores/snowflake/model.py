from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Set

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


class GrantedOn(Enum):
    """Define the type of object a grant is granted on."""

    TABLE = "TABLE"
    VIEW = "VIEW"
    MATERIALIZED_VIEW = "MATERIALIZED VIEW"
    ROLE = "ROLE"
    OTHER = "OTHER"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_str(cls, value: str) -> GrantedOn:
        try:
            return cls(value)
        except ValueError:
            return cls.OTHER


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
    """Define a resource, e.g. a db.schema.table db permission, and the permission level.
    The db_permission represents the db permission, e.g. SELECT, INSERT, etc.
    """

    name: List[str]
    permission_level: PermissionLevel
    db_permission: str
    granted_on: GrantedOn

    def __hash__(self) -> int:
        return hash(str(self.name))


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
