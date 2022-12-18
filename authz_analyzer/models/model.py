"""Generic data model.

Describes a permission to an asset that was granted to an identity. 
The way the permission was granted is described in the path.
"""
from dataclasses import dataclass
from enum import Enum, auto
from typing import List


class AssetType(Enum):
    """Define the types of assets that are stored at the datastores."""

    TABLE = auto()
    VIEW = auto()


class IdentityType(Enum):
    """Defines the types of identities that are used by the datastores."""

    USER = auto()  # Snowflake, GCP
    ROLE_LOGIN = auto()  # Postgres
    SERVICE_ACCOUNT = auto()  # GCP
    GROUP = auto()  # GCP
    WORKSPACE_ACCOUNT = auto()  # GCP
    CLOUD_IDENTITY_DOMAIN = auto()  # GCP

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


class AuthzPathElementType(Enum):
    """Defines the types of elements that can be used by datastores to grant permissions."""

    ROLE = auto()  # Used by Snowflake, and Postgres
    DATASET = auto()  # used by GCP
    TABLE = auto()  # used by GCP
    PROJECT = auto()  # used by GCP
    FOLDER = auto()  # used by GCP

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


class PermissionLevel(Enum):
    """Define the permission levels that can be granted to an asset."""

    READ = auto()
    WRITE = auto()
    FULL = auto()
    UNKNOWN = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


# Describes an element of the authorization entry path, for example a group or a role
# that was used to grant permission to an asset.
@dataclass
class AuthzPathElement:
    id: str
    name: str
    type: AuthzPathElementType
    note: str

    def __repr__(self):
        return f"{self.type} {self.id} {self.name} {self.note}"


@dataclass
class Asset:
    name: str
    type: AssetType


@dataclass
class Identity:
    id: str
    type: IdentityType
    name: str


@dataclass
class AuthzEntry:
    asset: Asset
    path: List[AuthzPathElement]
    identity: Identity
    permission: PermissionLevel

    def __repr__(self):
        return f"{self.identity} {self.permission} {self.asset} {self.path}"
