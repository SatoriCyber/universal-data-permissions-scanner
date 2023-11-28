from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from logging import Logger
from typing import Callable, Dict, Generator, List, Optional

from universal_data_permissions_scanner.datastores.databricks.model import (
    DataBricksIdentityName,
    DataBricksIdentityType,
    DatabricksParsedIdentity,
    DBPermissionLevel,
    Permission,
)
from universal_data_permissions_scanner.datastores.databricks.service.model import PrivilegeAssignments, TableType
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

DB_PERMISSION_PERMISSION_MAP = {
    DBPermissionLevel.OWNERSHIP: PermissionLevel.FULL,
    DBPermissionLevel.SELECT: PermissionLevel.READ,
    DBPermissionLevel.MODIFY: PermissionLevel.WRITE,
    DBPermissionLevel.ALL_PRIVILEGES: PermissionLevel.FULL,
}


class PolicyNodeType(Enum):
    CATALOG = "CATALOG"
    SCHEMA = "SCHEMA"
    TABLE = "TABLE"

    def __str__(self) -> str:
        return self.value


@dataclass
class PolicyNode:
    logger: Logger
    name: str
    node_type: PolicyNodeType
    parent: Optional[PolicyNode]
    location: int
    permissions: Dict[PermissionLevel, List[Permission]] = field(
        default_factory=lambda: {PermissionLevel.READ: [], PermissionLevel.WRITE: [], PermissionLevel.FULL: []}
    )

    def add_permission(self, identity: str, permissions: List[str], level: PolicyNodeType):
        if level != self.node_type and self.parent is not None:
            self.parent.add_permission(identity, permissions, level)
            return
        parsed_permissions: List[DBPermissionLevel] = []
        for permission in permissions:
            try:
                parsed_permission = DBPermissionLevel.from_str(permission)
            except ValueError:  # Permission which isn't relevant for us
                continue
            parsed_permissions.append(parsed_permission)

        if len(parsed_permissions) == 0:
            return
        permission_level = DB_PERMISSION_PERMISSION_MAP[max(parsed_permissions)]
        self.permissions[permission_level].append(Permission(identity, parsed_permissions))

    def add_ownership(self, identity: str):
        self.permissions[PermissionLevel.FULL].append(Permission(identity, [DBPermissionLevel.OWNERSHIP]))

    def iter_permissions_asset_name(
        self,
        asset: Asset,
        identity_resolver: Callable[
            [DataBricksIdentityName], Generator[Optional[DatabricksParsedIdentity], None, None]
        ],
        path: List[AuthzPathElement],
    ) -> Generator[AuthzEntry, None, None]:
        asset_name = ".".join(asset.name[0 : self.location])
        for permission_level, permissions in self.permissions.items():
            for permission in permissions:
                db_permissions = [str(db_permission) for db_permission in permission.db_permissions]
                for identity in identity_resolver(permission.identity):
                    if identity is None:
                        self.logger.info("Identity: %s, is built-in, skipping", permission.identity)
                        continue
                    authz_identity = Identity(
                        name=identity.name,
                        id=identity.id,
                        type=DATABRICKS_IDENTITY_TO_AUTHZ_IDENTITY_MAP[identity.type],
                    )
                    pop_counter = 0
                    if len(identity.groups) == 0:
                        self._build_path_identity_direct(path, authz_identity, db_permissions, asset_name)
                        pop_counter += 1
                    else:
                        pop_counter = self.handle_path_groups(path, identity, pop_counter, db_permissions, asset_name)
                    revered_path = list(reversed(path))
                    yield AuthzEntry(
                        identity=authz_identity, path=revered_path, asset=asset, permission=permission_level
                    )
                    path = path[:-pop_counter]
        if self.parent is not None:
            element = _build_authz_path_element(
                self.name,
                self.name,
                NODE_TYPE_PATH_TYPE_MAP[self.node_type],
                note=build_note_member_of(self.name, str(self.parent.node_type), self.parent.name),
            )
            path.append(element)
            yield from self.parent.iter_permissions_asset_name(asset, identity_resolver, path)

    def _build_path_identity_direct(
        self, path: List[AuthzPathElement], identity: Identity, db_permissions: List[str], asset_name: str
    ):
        str_db_permissions = ",".join(db_permissions)
        if self.node_type == PolicyNodeType.TABLE:
            element = _build_authz_path_element_no_note(
                identity.name,
                identity.id,
                IDENTITY_TYPE_TO_ELEMENT_TYPE[identity.type],
            )
        else:
            element = _build_authz_path_element_no_note(self.name, self.name, NODE_TYPE_PATH_TYPE_MAP[self.node_type])
        element.db_permissions = db_permissions
        element.notes = [
            AuthzNote(
                type=AuthzNoteType.GENERIC,
                note=f"{identity.type} {identity.name} has {str_db_permissions} permissions for {self.node_type} {asset_name}",
            )
        ]
        path.append(element)

    def handle_path_groups(
        self,
        path: List[AuthzPathElement],
        identity: DatabricksParsedIdentity,
        pop_counter: int,
        db_permissions: List[str],
        asset_name: str,
    ):
        str_db_permissions = ",".join(db_permissions)
        element = _build_authz_path_element(
            identity.groups[-1].name,
            identity.groups[-1].id,
            AuthzPathElementType.GROUP,
            note=build_note_permission_for(
                "GROUP", identity.groups[-1].name, str_db_permissions, str(self.node_type), asset_name
            ),
        )
        element.db_permissions = db_permissions
        path.append(element)
        group = identity.groups[0]
        groups_path: List[AuthzPathElement] = []
        for next_group in identity.groups[1:]:
            groups_path.append(
                _build_authz_path_element(
                    group.name,
                    group.id,
                    AuthzPathElementType.GROUP,
                    build_note_member_of(group.name, "GROUP", next_group.name),
                )
            )
            pop_counter += 1
            group = next_group
        path.extend(reversed(groups_path))
        pop_counter += 1
        return pop_counter


@dataclass
class CatalogNode(PolicyNode):
    def __init__(self, logger: Logger, name: str, ownership: str):
        super().__init__(logger, name, PolicyNodeType.CATALOG, None, 1)
        super().add_ownership(ownership)


@dataclass
class SchemaNode(PolicyNode):
    def __init__(self, logger: Logger, name: str, parent: CatalogNode, ownership: str):
        super().__init__(logger, name, PolicyNodeType.SCHEMA, parent, 2)
        super().add_ownership(ownership)


@dataclass
class ResourceNode(PolicyNode):
    def __init__(
        self,
        logger: Logger,
        name: str,
        parent: SchemaNode,
        resource_type: TableType,
        ownership: str,
    ):
        self.type = AssetType(str(resource_type))
        super().__init__(logger, name, PolicyNodeType.TABLE, parent, 3)
        super().add_ownership(ownership)

    def add_privilege_assignments(self, privilege_assignments: PrivilegeAssignments):
        for privilege in privilege_assignments["privileges"]:
            str_node_type = privilege.get("inherited_from_type", "TABLE")
            try:
                node_type = PolicyNodeType(str_node_type)
            except ValueError:
                self.logger.debug("Unknown element type %s", privilege["inherited_from_type"])
                continue
            self.add_permission(
                identity=privilege_assignments["principal"], permissions=[privilege["privilege"]], level=node_type
            )

    def get_full_resource_name(self) -> List[str]:
        if self.parent is None:
            raise ValueError("Schema cannot be None")
        if self.parent.parent is None:
            raise ValueError("Catalog cannot be None")
        return [self.parent.parent.name, self.parent.name, self.name]

    def iter_permissions(
        self,
        identity_resolver: Callable[
            [DataBricksIdentityName], Generator[Optional[DatabricksParsedIdentity], None, None]
        ],
    ) -> Generator[AuthzEntry, None, None]:
        if self.parent is None:
            raise ValueError("Parent of resource node cannot be None")
        asset = Asset(name=self.get_full_resource_name(), type=self.type)
        yield from self.iter_permissions_asset_name(asset, identity_resolver, [])


def _build_authz_path_element(
    name: str, element_id: str, path_element_type: AuthzPathElementType, note: AuthzNote
) -> AuthzPathElement:
    return AuthzPathElement(
        type=path_element_type,
        name=name,
        id=element_id,
        notes=[note],
    )


def _build_authz_path_element_no_note(
    name: str,
    element_id: str,
    path_element_type: AuthzPathElementType,
) -> AuthzPathElement:
    return AuthzPathElement(
        type=path_element_type,
        name=name,
        id=element_id,
        notes=[
            AuthzNote(
                type=AuthzNoteType.GENERIC,
                note="",
            )
        ],
    )


def build_note_member_of(member_name: str, granted_on_type: str, granted_on_name: str):
    return build_note(f"{member_name} is member of {granted_on_type} {granted_on_name}")


def build_note_permission_for(
    member_type: str, member_name: str, db_permissions: str, granted_on_type: str, granted_on_name: str
):
    return build_note(
        f"{member_type} {member_name} has {db_permissions} permissions for {granted_on_type} {granted_on_name}"
    )


def build_note(note: str):
    return AuthzNote(
        type=AuthzNoteType.GENERIC,
        note=note,
    )


NODE_TYPE_PATH_TYPE_MAP = {
    PolicyNodeType.CATALOG: AuthzPathElementType.CATALOG,
    PolicyNodeType.SCHEMA: AuthzPathElementType.SCHEMA,
    PolicyNodeType.TABLE: AuthzPathElementType.TABLE,
}

DATABRICKS_IDENTITY_TO_AUTHZ_IDENTITY_MAP = {
    DataBricksIdentityType.USER: IdentityType.USER,
    DataBricksIdentityType.SERVICE_PRINCIPAL: IdentityType.SERVICE_PRINCIPAL,
}

IDENTITY_TYPE_TO_ELEMENT_TYPE = {
    IdentityType.USER: AuthzPathElementType.USER,
    IdentityType.SERVICE_PRINCIPAL: AuthzPathElementType.SERVICE_PRINCIPAL,
}
