from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set

from authz_analyzer.models import PermissionLevel

RoleName = str

PERMISSION_LEVEL_MAP = {
    "SELECT": PermissionLevel.READ,
    "REFERENCES": PermissionLevel.READ,
    "INSERT": PermissionLevel.WRITE,
    "UPDATE": PermissionLevel.WRITE,
    "DELETE": PermissionLevel.WRITE,
    "TRUNCATE": PermissionLevel.WRITE,
    "TRIGGER": PermissionLevel.WRITE,
    "SUPER_USER": PermissionLevel.FULL,
}


@dataclass
class ResourceGrant:
    """Define a resource, e.g. a table, and the permission level."""

    name: str
    permission_level: PermissionLevel

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class DBRole:
    """Define a role, e.g. a user, and the roles it has, and if it can login."""

    name: str
    roles: Set[DBRole]
    can_login: bool

    @classmethod
    def new(cls, name: str, roles: Set[DBRole], can_login: bool):
        """Create a new DBRole."""
        return cls(name=name, roles=roles, can_login=can_login)

    def add_role(self, role: DBRole):
        self.roles.add(role)

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class AuthorizationModel:
    """Define the authorization model.
    Map a role to the roles it has, and the grants it has.
    Map a role to the grants it has.
    """

    role_to_roles: Dict[DBRole, Set[DBRole]]
    role_to_grants: Dict[RoleName, Set[ResourceGrant]]
