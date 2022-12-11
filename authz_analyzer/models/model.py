"""Generic data model.

Describes a permission to an asset that was granted to an identity. 
The way the permission was granted is described in the path.
"""
from dataclasses import dataclass
from enum import Enum, auto
from typing import List


@dataclass
class PermissionLevel(Enum):
    Read = auto()
    Write = auto()
    Full = auto()
    Unknown = auto()

    def __str__(self) -> str:
        return self.name


# Describes an element of the authorization entry path, for example a group or a role
# that was used to grant permission to an asset.
@dataclass
class AuthzPathElement:
    id: str
    name: str
    type: str
    note: str

    def __repr__(self):
        return f"{self.type} {self.id} {self.name} {self.note}"


@dataclass
class Asset:
    name: str
    type: str


@dataclass
class Identity:
    id: str
    type: str
    name: str


@dataclass
class AuthzEntry:
    asset: Asset
    path: List[AuthzPathElement]
    identity: Identity
    permission: PermissionLevel

    def __repr__(self):
        return f"{self.identity} {self.permission} {self.asset} {self.path}"
