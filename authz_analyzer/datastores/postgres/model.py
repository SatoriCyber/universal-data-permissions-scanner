from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set

from authz_analyzer.models import PermissionLevel

READ_LEVEL_PERMISSIONS = {"SELECT", "REFERENCES"}
WRITE_LEVEL_PERMISSIONS = {"INSERT", "UPDATE", "DELETE", "TRUNCATE", "TRIGGER"}
FULL_LEVEL_PERMISSIONS = {"SUPER_USER"}

RoleName = str


def permission_level_from_str(level: str):
    if level in READ_LEVEL_PERMISSIONS:
        return PermissionLevel.READ
    if level in WRITE_LEVEL_PERMISSIONS:
        return PermissionLevel.WRITE
    if level in FULL_LEVEL_PERMISSIONS:
        return PermissionLevel.FULL
    else:
        return PermissionLevel.UNKNOWN


@dataclass
class ResourceGrant:
    name: str
    permission_level: PermissionLevel

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class DBRole:
    name: str
    roles: Set[DBRole]
    can_login: bool

    @classmethod
    def new(cls, name: str, roles: Set[DBRole], can_login: bool):
        return cls(name=name, roles=roles, can_login=can_login)

    def add_role(self, role: DBRole):
        self.roles.add(role)

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class AuthorizationModel:
    role_to_roles: Dict[DBRole, Set[DBRole]]
    role_to_grants: Dict[RoleName, Set[ResourceGrant]]
