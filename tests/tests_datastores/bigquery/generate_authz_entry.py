from dataclasses import dataclass
from typing import Callable, List, Optional

from universal_data_permissions_scanner.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzNote,
    AuthzNoteType,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)

Username = str
UserId = str  # pylint: disable=invalid-name
Role = str


@dataclass
class User:
    id: UserId  # pylint: disable=invalid-name
    name: Username
    type: IdentityType


def generate_authz_entry(
    user: User,
    role: str,
    permission: PermissionLevel,
    path_generator: Callable[[Username, Role], List[AuthzPathElement]],
):
    return AuthzEntry(
        asset=Asset(["project1.dataset1.table1"], AssetType.TABLE, []),
        path=path_generator(user.name, role),
        identity=Identity(id=user.id, type=user.type, name=user.name, notes=[]),
        permission=permission,
    )


def generate_authz_with_db_permissions(
    user: User,
    role: str,
    permission: PermissionLevel,
    path_generator: Callable[[Username, Role], List[AuthzPathElement]],
    db_permissions: List[str],
):
    entry = generate_authz_entry(user, role, permission, path_generator)
    entry.path[0].db_permissions = db_permissions
    return entry


def generate_authz_path_element(
    authz_path_element_id: str,
    name: str,
    authz_path_element_type: AuthzPathElementType,
    note: str,
    db_permissions: Optional[List[str]] = None,
) -> AuthzPathElement:
    if db_permissions is None:
        db_permissions = []
    return AuthzPathElement(
        id=authz_path_element_id,
        name=name,
        type=authz_path_element_type,
        notes=[AuthzNote(note=note, type=AuthzNoteType.GENERIC)],
        db_permissions=db_permissions,
    )


def generate_authz_path_element_organization(note: str) -> AuthzPathElement:
    return generate_authz_path_element("organizations/1234", "1234", AuthzPathElementType.ORGANIZATION, note)


def generate_authz_path_element_folder(note: str) -> AuthzPathElement:
    return generate_authz_path_element("folders/folder1", "folder1_display_name", AuthzPathElementType.FOLDER, note)


def generate_authz_path_element_project(note: str) -> AuthzPathElement:
    return generate_authz_path_element("project1", "project1", AuthzPathElementType.PROJECT, note)


def generate_authz_path_element_dataset(note: str) -> AuthzPathElement:
    return generate_authz_path_element("dataset1", "dataset1_friendly_name", AuthzPathElementType.DATASET, note)


def generate_authz_path_element_table(note: str) -> AuthzPathElement:
    return generate_authz_path_element("project1.dataset1.table1", "table1", AuthzPathElementType.TABLE, note, [])


def generate_authz_path_element_role(
    granted_to: str, role: str, db_permissions: Optional[List[str]] = None
) -> AuthzPathElement:
    if db_permissions is None:
        db_permissions = []
    return generate_authz_path_element(
        role, role, AuthzPathElementType.ROLE, f"Role {role} is granted to {granted_to}", db_permissions
    )


def generate_authz_path_organization(
    granted_to: str, role: str = "OWNER", db_permissions: Optional[List[str]] = None
) -> List[AuthzPathElement]:
    return [
        generate_authz_path_element_role(granted_to, role, db_permissions),
        generate_authz_path_element_organization(f"{granted_to} has role {role}"),
        generate_authz_path_element_folder("folder folder1_display_name is included in organization 1234"),
        generate_authz_path_element_project("project project1 is included in folder folder1_display_name"),
        generate_authz_path_element_dataset("dataset dataset1_friendly_name is included in project project1"),
        generate_authz_path_element_table("table table1 is included in dataset dataset1_friendly_name"),
    ]


def generate_authz_path_folder(granted_to: str, role: str = "OWNER") -> List[AuthzPathElement]:
    return [
        generate_authz_path_element_role(granted_to, role),
        generate_authz_path_element_folder(f"{granted_to} has role {role}"),
        generate_authz_path_element_project("project project1 is included in folder folder1_display_name"),
        generate_authz_path_element_dataset("dataset dataset1_friendly_name is included in project project1"),
        generate_authz_path_element_table("table table1 is included in dataset dataset1_friendly_name"),
    ]


def generate_authz_path_project(
    granted_to: str, role: str, db_permissions: Optional[List[str]] = None
) -> List[AuthzPathElement]:
    return [
        generate_authz_path_element_role(granted_to, role, db_permissions),
        generate_authz_path_element_project(f"{granted_to} has role {role}"),
        generate_authz_path_element_dataset("dataset dataset1_friendly_name is included in project project1"),
        generate_authz_path_element_table("table table1 is included in dataset dataset1_friendly_name"),
    ]


def generate_authz_path_dataset(granted_to: str, role: str) -> List[AuthzPathElement]:
    return [
        generate_authz_path_element_role(granted_to, role),
        generate_authz_path_element_dataset(f"{granted_to} has role {role}"),
        generate_authz_path_element_table("table table1 is included in dataset dataset1_friendly_name"),
    ]


def generate_authz_path_table(
    granted_to: str, role: str, db_permissions: Optional[List[str]] = None
) -> List[AuthzPathElement]:
    return [
        generate_authz_path_element_role(granted_to, role, db_permissions),
        generate_authz_path_element_table(f"{granted_to} has role {role}"),
    ]
