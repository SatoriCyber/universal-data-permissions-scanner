"""Generic data model.

Describes a permission to an asset that was granted to an identity.
The way the permission was granted is described in the path.
Each writer will use the model to write the data in the format it needs.
Each datastore needs to create the model from the data it has, each entry should be of type AuthzEntry.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List


class AssetType(Enum):
    """Types of assets that are stored at the datastores."""

    TABLE = auto()
    VIEW = auto()
    MATERIALIZED_VIEW = auto()
    S3_BUCKET = auto()  # AWS S3
    COLLECTION = auto()  # MongoDB collection

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


class IdentityType(Enum):
    """Types of identities that are used by the datastores."""

    USER = auto()  # Snowflake, GCP, Redshift
    GROUP = auto()  # GCP, Redshift
    ROLE = auto()  # Redshift
    ROLE_LOGIN = auto()  # Postgres
    SERVICE_ACCOUNT = auto()  # GCP
    WORKSPACE_ACCOUNT = auto()  # GCP
    CLOUD_IDENTITY_DOMAIN = auto()  # GCP
    AWS_ACCOUNT = auto()  # AWS
    AWS_SERVICE = auto()  # AWS
    IAM_USER = auto()  # AWS
    IAM_ROLE = auto()  # AWS
    ROLE_SESSION = auto()  # AWS
    WEB_IDENTITY_SESSION = auto()  # AWS
    SAML_SESSION = auto()  # AWS
    FEDERATED_USER = auto()  # AWS
    ALL_USERS = auto()  # AWS
    ACCOUNT = auto()  # Snowflake

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


class AuthzPathElementType(Enum):
    """Types of elements that can be used by datastores to grant permissions."""

    USER = auto()  # Used by Redshift
    TEAM = auto()  # used by Mongo
    GROUP = auto()  # Used by Redshift
    ROLE = auto()  # Used by Snowflake, and Postgres
    DATASET = auto()  # used by GCP
    TABLE = auto()  # used by GCP
    PROJECT = auto()  # used by GCP
    FOLDER = auto()  # used by GCP
    ORGANIZATION = auto()  # used by GCP
    AWS_ACCOUNT = auto()  # AWS
    AWS_SERVICE = auto()  # AWS
    IAM_USER = auto()  # AWS
    IAM_GROUP = auto()  # AWS
    IAM_INLINE_POLICY = auto()  # AWS
    IAM_POLICY = auto()  # AWS
    IAM_ROLE = auto()  # AWS
    ROLE_SESSION = auto()  # AWS
    WEB_IDENTITY_SESSION = auto()  # AWS
    SAML_SESSION = auto()  # AWS
    FEDERATED_USER = auto()  # AWS
    ALL_USERS = auto()  # AWS
    CLUSTER = auto()  # Mongo Atlas
    RESOURCE_POLICY = auto()  # AWS
    SHARE = auto()  # Snowflake

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


class PermissionLevel(Enum):
    """Permission levels that can be granted to an asset."""

    UNKNOWN = 0
    READ = 1
    WRITE = 2
    FULL = 3

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)

    def __lt__(self, other: PermissionLevel) -> bool:
        return self.value < other.value

    def __ge__(self, other: PermissionLevel) -> bool:
        return self.value >= other.value


@dataclass
class AuthzPathElement:
    """Element of the authorization entry path which grants access.
    For example a group or a role that was used to grant permission to an asset.
    """

    id: str
    name: str
    type: AuthzPathElementType
    note: str
    db_permissions: List[str] = field(default_factory=list)

    def __repr__(self):
        return f"{self.type} {self.id} {self.name} {self.note}"


@dataclass
class Asset:
    """Datastore asset.
    name: The id of the asset encoded in a list, for example ['db', 'schema', 'table'].
    type: The type of the asset, for example TABLE or VIEW.
    """

    name: List[str]
    type: AssetType


@dataclass
class Identity:
    """An identity which has access to an asset.
    For example, User, Role, ServiceAccount etc'
    """

    id: str
    type: IdentityType
    name: str


@dataclass
class AuthzEntry:
    """A single entry which describe access to an asset.
    For example, USER has role ROLE1 which grants access to TABLE1.
    """

    asset: Asset
    path: List[AuthzPathElement]
    identity: Identity
    permission: PermissionLevel

    def __repr__(self):
        return f"{self.identity} {self.permission} {self.asset} {self.path}"
