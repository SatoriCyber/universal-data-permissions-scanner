"""Defines the objects returned by the MongoDB API."""
from typing import List, TypedDict


class ResourceEntry(TypedDict):
    """Define a MongoDB resource.
    Returned by the rolesInfo command.
    """

    db: str
    collection: str


class AssignedRole(TypedDict):
    """Define a MongoDB role assignment.
    returned by the usersInfo command.
    """

    role: str
    db: str


class UserEntry(TypedDict):
    """Define a MongoDB user.
    Returned by the usersInfo command.
    """

    userId: bytes
    user: str
    db: str
    roles: List[AssignedRole]


class UserInfoResponseEntry(TypedDict):
    """Define the response from the usersInfo command."""

    users: List[UserEntry]


class PrivilegeEntry(TypedDict):
    """Define a MongoDB privilege.
    Returned by the rolesInfo command.
    """

    resource: ResourceEntry
    actions: List[str]


class RoleEntry(TypedDict):
    """Define a MongoDB role.
    Returned by the rolesInfo command.
    """

    role: str
    db: str
    privileges: List[PrivilegeEntry]
    inheritedRoles: List[AssignedRole]


class RolesInfoEntry(TypedDict):
    """Define the response from the rolesInfo command."""

    roles: List[RoleEntry]
