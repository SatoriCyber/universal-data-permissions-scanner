from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List


class DBPermissionLevel(Enum):
    OWNERSHIP = 3
    SELECT = 1
    MODIFY = 2
    ALL_PRIVILEGES = 3

    def __lt__(self, other: DBPermissionLevel):
        return self.value < other.value

    def __str__(self) -> str:
        return self.name

    @classmethod
    def from_str(cls, permission: str):
        if permission == "OWNERSHIP":
            return cls.OWNERSHIP
        if permission == "SELECT":
            return cls.SELECT
        if permission == "MODIFY":
            return cls.MODIFY
        if permission == "ALL_PRIVILEGES":
            return cls.ALL_PRIVILEGES
        raise ValueError(f"Unknown permission: {permission}")


DataBricksIdentityName = str
DataBricksIdentityId = str


@dataclass
class Permission:
    identity: str
    db_permissions: List[DBPermissionLevel]


@dataclass
class DatabricksParsedIdentity:
    name: str
    id: str  # pylint: disable=invalid-name
    groups: List[ParsedGroup]
    type: DataBricksIdentityType


@dataclass
class ParsedGroup:
    id: str  # pylint: disable=invalid-name
    name: str


class DataBricksIdentityType(Enum):
    USER = "USER"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"

    def __str__(self) -> str:
        return self.value
