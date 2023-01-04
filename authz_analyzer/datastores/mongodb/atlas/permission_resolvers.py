"""Atlas Role/Permission resolvers to Authz Permission"""


from enum import Enum, auto
from authz_analyzer.models.model import PermissionLevel


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

PRIVILEGE_MAPPING = {
    "find": PermissionLevel.READ,
    "insert": PermissionLevel.WRITE,
    "remove": PermissionLevel.WRITE,
    "update": PermissionLevel.WRITE,
    "changeStream": PermissionLevel.READ,
    "dropCollection": PermissionLevel.WRITE,
    "dropDatabase": PermissionLevel.WRITE,
    "listCollections": PermissionLevel.READ,
    "listIndexes": PermissionLevel.READ,
    "listDatabases": PermissionLevel.READ,
    "anyAction": PermissionLevel.FULL,
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