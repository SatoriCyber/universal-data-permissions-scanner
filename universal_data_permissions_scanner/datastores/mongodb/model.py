from __future__ import annotations

from dataclasses import dataclass
from typing import List, Set

from universal_data_permissions_scanner.datastores.mongodb.service_model import RoleEntry
from universal_data_permissions_scanner.models.model import AuthzPathElement, PermissionLevel


@dataclass
class InheritedRole:
    """Define a MongoDB inherited role."""

    name: str
    database: str

    def __hash__(self) -> int:
        return hash(self.name) + hash(self.database)


@dataclass
class Resource:
    """Define a MongoDB resource."""

    database: str
    collection: str

    def __hash__(self) -> int:
        return hash(self.database) + hash(self.collection)


@dataclass
class Privilege:
    """Define a MongoDB privilege."""

    resource: Resource
    actions: List[str]

    def __hash__(self) -> int:
        return hash(self.resource) + hash(tuple(self.actions))


@dataclass
class Role:
    """Define a MongoDB role."""

    name: str
    db: str  # pylint: disable=invalid-name
    inherited_roles: List[InheritedRole]
    privileges: List[Privilege]

    @classmethod
    def build_from_response(cls, entry: RoleEntry):
        """Build a role from the response."""
        inherited_roles = [InheritedRole(name=role["role"], database=role["db"]) for role in entry["inheritedRoles"]]
        privileges = [
            Privilege(
                resource=Resource(privilege["resource"]["db"], privilege["resource"]["collection"]),
                actions=privilege["actions"],
            )
            for privilege in entry["privileges"]
        ]
        return cls(
            name=entry["role"],
            db=entry["db"],
            inherited_roles=inherited_roles,
            privileges=privileges,
        )


@dataclass
class AdminRole:
    """Define a MongoDB admin role."""

    name: str
    permission_level: PermissionLevel
    path: List[AuthzPathElement]

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class AdminUser:
    """Define a MongoDB admin user with a single role."""

    id: str  # pylint: disable=invalid-name
    name: str
    roles: Set[AdminRole]

    def __hash__(self) -> int:
        return hash(self.id)
