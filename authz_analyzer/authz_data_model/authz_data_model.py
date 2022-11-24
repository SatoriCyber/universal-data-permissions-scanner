from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

READ_LEVEL_PERMISSIONS = {"SELECT", "REFERENCES"}
WRITE_LEVEL_PERMISSIONS = {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REBUILD", "OWNERSHIP"}

@dataclass
class PermissionLevel(Enum):
    Read = auto()
    ReadWrite = auto()
    Unknown = auto()

    @classmethod
    def from_str(cls, level: str):
        if level in READ_LEVEL_PERMISSIONS:
            return PermissionLevel.Read
        if level in WRITE_LEVEL_PERMISSIONS:
            return PermissionLevel.ReadWrite
        else:
            return PermissionLevel.Unknown
    

    def __str__(self) -> str:
        return self.name


@dataclass
class TableGrant:
    name: str
    permission_level: PermissionLevel


@dataclass
class DBRole:
    name: str
    roles: set[DBRole]
    grants: set[TableGrant]

    @classmethod
    def new(cls, name: str, roles: set[DBRole] = set(), grants: set[TableGrant] = set()):
        return cls(name=name, roles=roles, grants=grants)

    def add_role(self, role: DBRole):
        self.roles.add(role)

    def add_grant(self, grant: TableGrant):
        self.grants.add(grant)
    

@dataclass
class DBUser:
    name: str
    roles: set[DBRole]
    grants: set[TableGrant]

    @classmethod
    def new(cls, name: str, roles: set[DBRole] = set(), grants: set[TableGrant] = set()) -> DBUser:
        return cls(name=name, roles=roles, grants=grants)

    def add_role(self, role: DBRole):
        self.roles.add(role)

    def add_grant(self, grant: TableGrant):
        self.grants.add(grant)


@dataclass
class AuthorizationModel:
    user_grants: dict[str, DBUser]
    roles_grants: dict[str, DBRole]
