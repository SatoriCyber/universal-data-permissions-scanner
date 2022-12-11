from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set

from authz_analyzer.models import PermissionLevel

READ_LEVEL_PERMISSIONS = {"SELECT", "REFERENCES"}
WRITE_LEVEL_PERMISSIONS = {"INSERT", "UPDATE", "DELETE", "TRUNCATE", "REBUILD"}
FULL_LEVEL_PERMISSIONS = {"OWNERSHIP", "ALL"}


@dataclass
class User:
    name: str
    id: str

    def __hash__(self) -> int:
        return hash(self.id)


RoleName = str
Username = User


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
    roles: Set[DBRole]

    @classmethod
    def new(cls, name: str, roles: Set[DBRole]):
        return cls(name=name, roles=roles)

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class AuthorizationModel:
    users_to_roles: Dict[Username, Set[DBRole]]
    role_to_roles: Dict[RoleName, Set[DBRole]]
    roles_to_grants: Dict[RoleName, Set[ResourceGrant]]
