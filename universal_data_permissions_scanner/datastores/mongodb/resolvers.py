from universal_data_permissions_scanner.models.model import PermissionLevel

BUILT_IN_ROLES_MAP = {
    "read": PermissionLevel.READ,
    "readWrite": PermissionLevel.WRITE,
    "dbAdmin": PermissionLevel.FULL,
    "dbOwner": PermissionLevel.FULL,
    "userAdmin": PermissionLevel.FULL,
}

BUILT_IN_CLUSTER_ROLES_MAP = {
    "clusterAdmin": PermissionLevel.FULL,
    "backup": PermissionLevel.FULL,
    "restore": PermissionLevel.FULL,
    "readAnyDatabase": PermissionLevel.READ,
    "readWriteAnyDatabase": PermissionLevel.WRITE,
    "userAdminAnyDatabase": PermissionLevel.FULL,
    "dbAdminAnyDatabase": PermissionLevel.FULL,
    "root": PermissionLevel.FULL,
    "__system": PermissionLevel.FULL,
}

PRIVILEGE_MAP = {
    "find": PermissionLevel.READ,
    "insert": PermissionLevel.WRITE,
    "remove": PermissionLevel.WRITE,
    "update": PermissionLevel.WRITE,
    "createRole": PermissionLevel.FULL,
    "createUser": PermissionLevel.FULL,
    "dropCollection": PermissionLevel.WRITE,
    "grantRole": PermissionLevel.FULL,
    "dropDatabase": PermissionLevel.WRITE,
    "anyAction": PermissionLevel.FULL,
    "internal": PermissionLevel.FULL,
}


def get_permission_level(role: str):
    """Get permission level from role."""
    return BUILT_IN_ROLES_MAP.get(role)


def get_permission_level_cluster(role: str):
    """Get permission level from role."""
    return BUILT_IN_CLUSTER_ROLES_MAP.get(role)


def get_permission_level_privilege(privilege: str):
    """Get permission level from privilege."""
    return PRIVILEGE_MAP.get(privilege)
