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

from aws_ptrp.utils.serde import serde_enum_field
from serde import field as serde_field  # pylint: disable=import-error #type: ignore
from serde import serde  # pylint: disable=import-error #type: ignore


class AssetType(Enum):
    """Types of assets that are stored at the datastores."""

    TABLE = "TABLE"
    VIEW = "VIEW"
    MATERIALIZED_VIEW = "MATERIALIZED_VIEW"
    S3_BUCKET = "S3_BUCKET"  # AWS S3
    COLLECTION = "COLLECTION"  # MongoDB collection
    TOAST_TABLE = "TOAST_TABLE"  # Postgres
    FOREIGN_TABLE = "FOREIGN_TABLE"  # Postgres
    PARTITION_TABLE = "PARTITION_TABLE"  # Postgres
    EXTERNAL = "EXTERNAL"  # Databricks
    MANAGED = "MANAGED"  # Databricks
    STREAMING_TABLE = "STREAMING_TABLE"  # Databricks

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
    ANONYMOUS_USER = auto()  # AWS
    ACCOUNT = auto()  # Snowflake
    DB_USER = auto()  # MongoDB Atlas
    ORG_USER = auto()  # MongoDB Atlas
    CLUSTER = auto()  # AWS Redshift Cluster
    SERVICE_PRINCIPAL = auto()  # Databricks
    IAM_IDENTITY_CENTER_USER = auto()  # AWS

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
    ANONYMOUS_USER = auto()  # AWS
    CLUSTER = auto()  # Mongo Atlas
    RESOURCE_POLICY = auto()  # AWS
    SHARE = auto()  # Snowflake
    CATALOG = auto()  # Databricks
    SCHEMA = auto()  # Databricks
    SERVICE_PRINCIPAL = auto()  # Databricks
    IAM_IDENTITY_CENTER_USER = auto()  # AWS
    IAM_IDENTITY_CENTER_GROUP = auto()  # AWS
    PERMISSION_SET = auto()  # AWS

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


class AuthzNoteType(Enum):
    """Note element type."""

    GENERIC = auto()
    AWS_POLICY_STMT_DENY_WITH_CONDITION = auto()
    AWS_POLICY_STMT_SKIPPING_DENY_WITH_S3_NOT_RESOURCE = auto()
    IAM_IDENTITY_CENTER_USER_DESCRIPTION = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


@serde
@dataclass
class AuthzNote:
    """Note element to be use in a the authorization entry elements identity/path/assert."""

    note: str
    type: AuthzNoteType = serde_field(serializer=lambda x: x.name, deserializer=lambda x: AuthzNoteType[x])

    def __str__(self) -> str:
        return f"{self.type}: {self.note}"

    def __repr__(self) -> str:
        return f"{self.type}: {self.note}"

    @classmethod
    def to_generic_note(cls, note: str) -> AuthzNote:
        return AuthzNote(note=note, type=AuthzNoteType.GENERIC)


@serde
@dataclass
class AuthzPathElement:
    """Element of the authorization entry path which grants access.
    For example a group or a role that was used to grant permission to an asset.
    """

    id: str  # pylint: disable=invalid-name
    name: str
    type: AuthzPathElementType = serde_enum_field(AuthzPathElementType)
    notes: List[AuthzNote] = field(default_factory=list)
    db_permissions: List[str] = field(default_factory=list)

    # def __repr__(self):
    #     return f"{self.type} {self.id} {self.name} {self.notes}"

    def __str__(self) -> str:
        result = f"{self.type} {self.name}"
        if len(self.db_permissions) != 0:
            result += f" provides permissions {self.db_permissions}"
        if len(self.notes) != 0:
            result += f" notes {self.notes}"
        return result


@serde
@dataclass
class Asset:
    """Datastore asset.
    name: The id of the asset encoded in a list, for example ['db', 'schema', 'table'].
    type: The type of the asset, for example TABLE or VIEW.
    """

    name: List[str]
    type: AssetType = serde_enum_field(AssetType)
    notes: List[AuthzNote] = field(default_factory=list)

    def __str__(self) -> str:
        result = f"{self.type}: {'.'.join(self.name)}"
        if len(self.notes) != 0:
            result += f", notes: {self.notes}"
        return result


@serde
@dataclass
class Identity:
    """An identity which has access to an asset.
    For example, User, Role, ServiceAccount etc'
    """

    id: str  # pylint: disable=invalid-name
    name: str
    type: IdentityType = serde_enum_field(IdentityType)
    notes: List[AuthzNote] = field(default_factory=list)

    def __str__(self) -> str:
        result = f"{self.type}: {self.name}"
        if len(self.notes) != 0:
            result += f", notes: {self.notes}"
        return result


@serde
@dataclass
class AuthzEntry:
    """A single entry which describe access to an asset.
    For example, USER has role ROLE1 which grants access to TABLE1.
    """

    asset: Asset
    path: List[AuthzPathElement]
    identity: Identity
    permission: PermissionLevel = serde_enum_field(PermissionLevel)

    def __repr__(self):
        return f"{self.identity} {self.permission} {self.asset} {self.path}"
