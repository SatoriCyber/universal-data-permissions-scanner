from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set

from universal_data_permissions_scanner.models import PermissionLevel

ResourceName = List[str]


@dataclass
class DataShare:
    """Define a dataShare."""

    name: str
    id: str  # pylint: disable=invalid-name
    share_to_accounts: List[str]
    resources: Dict[PermissionLevel, Dict[DataSharePrivilege, Set[PermissionType]]]
    roles: Set[DBRole] = field(default_factory=set)

    @classmethod
    def new(cls, name: str, share_id: str, share_to_accounts: List[str]):
        resources: Dict[PermissionLevel, Dict[DataSharePrivilege, Set[PermissionType]]] = {
            PermissionLevel.READ: {},
            PermissionLevel.WRITE: {},
            PermissionLevel.FULL: {},
        }
        return cls(name=name, id=share_id, share_to_accounts=share_to_accounts, resources=resources)

    def __hash__(self) -> int:
        return hash(self.name)

    def add_role(self, role: DBRole):
        self.roles.add(role)

    def add_privilege(
        self,
        permission_level: PermissionLevel,
        granted_on: GrantedOn,
        resource_name: ResourceName,
        database_permission: PermissionType,
    ):
        datashare_priv = DataSharePrivilege(granted_on=granted_on, resource_name=resource_name)
        self.resources[permission_level].setdefault(datashare_priv, set()).add(database_permission)


class DataShareKind(Enum):
    """Define the kind of dataShare, OUTBOUND or INBOUND."""

    OUTBOUND = "OUTBOUND"
    INBOUND = "INBOUND"


class PermissionType(Enum):
    """Define the type of permission level, e.g. select, usage, etc'."""

    USAGE = "USAGE"
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    TRUNCATE = "TRUNCATE"
    REFERENCES = "REFERENCES"
    REBUILD = "REBUILD"
    OWNERSHIP = "OWNERSHIP"


@dataclass
class DataSharePrivilege:
    """Define a dataShare privilege.
    granted_on: table/view/mview
    permission_level: read/write/full
    database_permission: select/insert/update/delete
    resource_name: db.schema.table
    database_roles: Snowflake support that the share has a role that grants the permissions.
    """

    granted_on: GrantedOn
    resource_name: List[str]

    def __hash__(self) -> int:
        return hash(self.granted_on) + hash(str(self.resource_name))


PERMISSION_LEVEL_MAP = {
    PermissionType.SELECT: PermissionLevel.READ,
    PermissionType.REFERENCES: PermissionLevel.READ,
    PermissionType.INSERT: PermissionLevel.WRITE,
    PermissionType.UPDATE: PermissionLevel.WRITE,
    PermissionType.DELETE: PermissionLevel.WRITE,
    PermissionType.TRUNCATE: PermissionLevel.WRITE,
    PermissionType.REBUILD: PermissionLevel.WRITE,
    PermissionType.OWNERSHIP: PermissionLevel.FULL,
}


class GrantedOn(Enum):
    """Define the type of object a grant is granted on."""

    TABLE = "TABLE"
    VIEW = "VIEW"
    MATERIALIZED_VIEW = "MATERIALIZED VIEW"
    ROLE = "ROLE"
    OTHER = "OTHER"
    DATABASE_ROLE = "DATABASE_ROLE"
    DATABASE = "DATABASE"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_str(cls, value: str) -> GrantedOn:
        try:
            return cls(value)
        except ValueError:
            return cls.OTHER


@dataclass
class User:
    name: str
    id: str  # pylint: disable=invalid-name

    def __hash__(self) -> int:
        return hash(self.id)


RoleName = str
Username = User


@dataclass
class ResourceGrant:
    """Define a resource, e.g. a db.schema.table db permission, and the permission level.
    The db_permission represents the db permission, e.g. SELECT, INSERT, etc.
    """

    name: List[str]
    permission_level: PermissionLevel
    db_permissions: List[PermissionType]
    granted_on: GrantedOn

    def __hash__(self) -> int:
        return hash(str(self.name))


@dataclass
class DBRole:
    """Define a role which grants access from a user to a resource."""

    name: str
    roles: Set[DBRole]

    @classmethod
    def new(cls, name: str, roles: Set[DBRole]):
        """Creates a new DBRole."""
        return cls(name=name, roles=roles)

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class AuthorizationModel:
    """Define the authorization model.
    User to roles -> map a user to the roles it has
    Role to roles -> map a role to the roles it has
    Role to grants -> map a role to the grants it has
    """

    users_to_roles: Dict[Username, Set[DBRole]]
    role_to_roles: Dict[RoleName, Set[DBRole]]
    roles_to_grants: Dict[RoleName, Set[ResourceGrant]]
    shares: Set[DataShare]
