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
    
    def __hash__(self) -> int:
        return hash(self.name) + hash(self.value)


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
class AuthzEntry:
    asset: str
    path: List[AuthzPathElement]
    identity: str
    permission: PermissionLevel

    def __repr__(self):
        return f"{self.identity} {self.permission} {self.asset} {self.path}"
