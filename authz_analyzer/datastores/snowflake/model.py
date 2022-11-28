from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set

from authz_analyzer.models import PermissionLevel


READ_LEVEL_PERMISSIONS = {"SELECT", "REFERENCES"}
WRITE_LEVEL_PERMISSIONS = {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REBUILD", "ALL"}
FULL_LEVEL_PERMISSIONS = {"OWNERSHIP"}


def permission_level_from_str(level: str):
    if level in READ_LEVEL_PERMISSIONS:
        return PermissionLevel.Read
    if level in WRITE_LEVEL_PERMISSIONS:
        return PermissionLevel.Write
    if level in FULL_LEVEL_PERMISSIONS:
        return PermissionLevel.Full
    else:
        return PermissionLevel.Unknown



@dataclass
class ResourceGrant:
    name: str
    permission_level: PermissionLevel

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class DBRole:
    name: str
    roles: set[DBRole]

    @classmethod
    def new(cls, name: str, roles: set[DBRole] = set()):
        return cls(name=name, roles=roles)

    def add_role(self, role: DBRole):
        self.roles.add(role)

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class DBUser:
    name: str
    roles: set[DBRole]

    @classmethod
    def new(cls, name: str, roles: set[DBRole] = set()) -> DBUser:
        return cls(name=name, roles=roles)

    def add_role(self, role: DBRole):
        self.roles.add(role)

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class AuthorizationModel:
    users_to_roles: Dict[str, DBUser]
    role_to_roles: Dict[str, Set[DBRole]]
    roles_to_grants: Dict[str, Set[ResourceGrant]]