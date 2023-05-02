"""Defines the objects returned by the Atlas admin API."""
from typing import List, TypedDict


class DataBaseUserEntryRoleRequired(TypedDict):
    """Python doesn't support typed dict with some required fields and some optional.
    Only through inheritance.
    So those fields.
    """

    databaseName: str
    roleName: str


class DataBaseUserEntryRole(DataBaseUserEntryRoleRequired, total=False):
    """Inherit from DataBaseUserEntryRoleRequired to get required fields."""

    collectionName: str


class DataBaseUserEntryScope(TypedDict):
    name: str
    type: str


class DataBaseUserEntry(TypedDict):
    username: str
    databaseName: str
    scopes: List[DataBaseUserEntryScope]
    roles: List[DataBaseUserEntryRole]


class OrganizationRole(TypedDict):
    """An organization role."""

    roleName: str


class OrganizationUserEntry(TypedDict):
    """An organization user entry."""

    id: str  # pylint: disable=invalid-name
    username: str
    emailAddress: str
    databaseName: str
    roles: List[OrganizationRole]
    teamIds: List[str]


class ProjectTeamEntry(TypedDict):
    """A project team entry."""

    teamId: str
    roleNames: List[str]


class OrganizationTeamEntry(TypedDict):
    """An organization team entry."""

    id: str  # pylint: disable=invalid-name
    name: str


class ClusterConnectionStringEntry(TypedDict):
    """Connection string from groups/{groupId}/clusters"""

    standardSrv: str


class ClusterEntry(TypedDict):
    """Single entry from groups/{groupId}/clusters."""

    id: str  # pylint: disable=invalid-name
    name: str
    connectionStrings: ClusterConnectionStringEntry


class InheritedRoleEntry(TypedDict):
    """Inherited role entry."""

    role: str
    db: str


class ResourceEntry(TypedDict):
    """Resource entry."""

    cluster: bool
    collection: str
    db: str


class ActionEntry(TypedDict):
    """Action entry."""

    action: str
    resources: List[ResourceEntry]


class CustomRoleEntry(TypedDict):
    """A custom role entry."""

    roleName: str
    actions: List[ActionEntry]
    inheritedRoles: List[InheritedRoleEntry]


class ProjectInfo(TypedDict):
    """A project info entry."""

    id: str  # pylint: disable=invalid-name
    name: str
    orgId: str


class OrganizationEntry(TypedDict):
    """An organization entry."""

    id: str  # pylint: disable=invalid-name
    name: str
