"""Atlas Role/Permission resolvers to Authz Permission"""


from enum import Enum, auto

from universal_data_permissions_scanner.datastores.mongodb.atlas.model import Permission
from universal_data_permissions_scanner.models.model import PermissionLevel


class PermissionScope(Enum):
    """Define the scope of the permission."""

    COLLECTION = auto()
    PROJECT = auto()
    DATABASE = auto()


BUILT_IN_ROLE_MAPPING_ORGANIZATION = {
    "ORG_OWNER": PermissionLevel.FULL,
    "ORG_READ_ONLY": PermissionLevel.READ,
}

BUILT_IN_ROLE_MAPPING_PROJECT = {
    "GROUP_OWNER": PermissionLevel.FULL,
    "GROUP_DATA_ACCESS_ADMIN": PermissionLevel.FULL,
    "GROUP_DATA_ACCESS_READ_WRITE": PermissionLevel.FULL,
    "GROUP_DATA_ACCESS_READ_ONLY": PermissionLevel.READ,
}


BUILT_IN_ROLE_MAPPING_DATABASE = {
    "atlasAdmin": (PermissionLevel.FULL, PermissionScope.PROJECT),
    "readWriteAnyDatabase": (PermissionLevel.FULL, PermissionScope.PROJECT),
    "readAnyDatabase": (PermissionLevel.READ, PermissionScope.PROJECT),
    "dbAdmin": (PermissionLevel.FULL, PermissionScope.DATABASE),
    "dbAdminAnyDatabase": (PermissionLevel.FULL, PermissionScope.PROJECT),
    "read": (PermissionLevel.READ, PermissionScope.COLLECTION),
    "readWrite": (PermissionLevel.WRITE, PermissionScope.COLLECTION),
}

ACTION_MAPPING = {
    Permission.FIND: PermissionLevel.READ,
    Permission.INSERT: PermissionLevel.WRITE,
    Permission.REMOVE: PermissionLevel.WRITE,
    Permission.UPDATE: PermissionLevel.WRITE,
    Permission.DROP_COLLECTION: PermissionLevel.WRITE,
    Permission.DROP_DATABASE: PermissionLevel.WRITE,
    Permission.RENAME_COLLECTION_SAME_DB: PermissionLevel.READ,
    Permission.LIST_COLLECTIONS: PermissionLevel.READ,
    Permission.SQL_GET_SCHEMA: PermissionLevel.READ,
    Permission.SQL_SET_SCHEMA: PermissionLevel.WRITE,
    Permission.OUT_TO_S3: PermissionLevel.READ,
}


def resolve_organization_role(role: str):
    """Resolve the permission level for a given organization role."""
    return BUILT_IN_ROLE_MAPPING_ORGANIZATION.get(role)


def resolve_project_role(role: str):
    """Resolve the permission level for a given project role."""
    return BUILT_IN_ROLE_MAPPING_PROJECT.get(role)


def resolve_database_role(role: str):
    """Resolve the permission level and scope for a given database role."""
    return BUILT_IN_ROLE_MAPPING_DATABASE.get(role)


def resolve_permission(permission: Permission):
    """Resolve MongoDB permission to permission level."""
    return ACTION_MAPPING.get(permission)
