from typing import List
from unittest.mock import call

from universal_data_permissions_scanner.datastores.databricks.service.model import Group, ParsedUser, ServicePrincipal
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
from tests.tests_datastores.databricks.mocks import TestCatalog, TestSchema, TestTable


def build_catalog_user_access(
    user: ParsedUser,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_catalog_identity(build_identity_user(user), table, permission_level, db_permissions)


def build_catalog_service_principal_access(
    service_principal: ServicePrincipal,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_catalog_identity(
        build_identity_service_principal(service_principal), table, permission_level, db_permissions
    )


def build_schema_user_access(
    user: ParsedUser,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_schema_service_identity(build_identity_user(user), table, permission_level, db_permissions)


def build_schema_service_principal_access(
    service_principal: ServicePrincipal,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_schema_service_identity(
        build_identity_service_principal(service_principal), table, permission_level, db_permissions
    )


def build_direct_access_user(
    user: ParsedUser,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_direct_access_identity(build_identity_user(user), table, permission_level, db_permissions)


def build_direct_access_service_principal(
    service_principal: ServicePrincipal,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_direct_access_identity(
        build_identity_service_principal(service_principal), table, permission_level, db_permissions
    )


def build_user_member_of_group_direct_access(
    user: ParsedUser,
    group: Group,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_identity_member_of_group_direct_access(
        build_identity_user(user), group, table, permission_level, db_permissions
    )


def build_user_group_in_groups(
    user: ParsedUser,
    groups: List[Group],
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_identity_member_of_group_in_groups(
        build_identity_user(user), groups, table, permission_level, db_permissions
    )


def build_schema_user_group_in_groups(
    user: ParsedUser,
    groups: List[Group],
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_identity_member_of_schema_group_in_groups(
        build_identity_user(user), groups, table, permission_level, db_permissions
    )


def build_catalog_user_group_in_groups(
    user: ParsedUser,
    groups: List[Group],
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_identity_member_of_catalog_group_in_groups(
        build_identity_user(user), groups, table, permission_level, db_permissions
    )


def build_service_principal_member_of_group_direct_access(
    service_principal: ServicePrincipal,
    group: Group,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_identity_member_of_group_direct_access(
        build_identity_service_principal(service_principal), group, table, permission_level, db_permissions
    )


def build_user_schema_group_access(
    user: ParsedUser,
    group: Group,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_identity_member_of_group_schema_access(
        build_identity_user(user), group, table, permission_level, db_permissions
    )


def build_service_principal_schema_group_access(
    service_principal: ServicePrincipal,
    group: Group,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_identity_member_of_group_schema_access(
        build_identity_service_principal(service_principal), group, table, permission_level, db_permissions
    )


def build_user_catalog_group_access(
    user: ParsedUser,
    group: Group,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_identity_member_of_group_catalog_access(
        build_identity_user(user), group, table, permission_level, db_permissions
    )


def build_service_principal_catalog_group_access(
    service_principal: ServicePrincipal,
    group: Group,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    return build_identity_member_of_group_catalog_access(
        build_identity_service_principal(service_principal), group, table, permission_level, db_permissions
    )


def build_direct_access_identity(
    identity: Identity,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    table_name = ".".join(table.get_full_name())
    entry = build_authz_entry_no_path(identity, table, permission_level)
    identity_path = build_path_element_identity_no_notes(identity)
    identity_path.notes = [build_note_identity_has_access_table(identity, db_permissions, table_name)]
    identity_path.db_permissions = db_permissions
    entry.path = [identity_path]
    return call(entry)


def build_identity_member_of_group_direct_access(
    identity: Identity,
    group: Group,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    table_name = ".".join(table.get_full_name())
    entry = build_authz_entry_no_path(identity, table, permission_level)
    group_path = build_path_element_group_name_no_notes(group)
    group_path.notes = [build_note_group_has_access_table(group, db_permissions, table_name)]
    group_path.db_permissions = db_permissions
    entry.path.append(group_path)
    return call(entry)


def build_identity_member_of_group_in_groups(
    identity: Identity,
    groups: List[Group],
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    entry = build_authz_entry_no_path(identity, table, permission_level)
    member_of = groups[0]
    for group in groups[1:]:
        entry.path.append(build_path_element_group_member_of_group(member_of, group))
        member_of = group
    entry.path.append(build_path_element_group_access_table(groups[-1], table, db_permissions))
    return call(entry)


def build_identity_member_of_schema_group_in_groups(
    identity: Identity,
    groups: List[Group],
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    schema = table.get_schema()
    entry = build_authz_entry_no_path(identity, table, permission_level)
    member_of = groups[0]
    for group in groups[1:]:
        entry.path.append(build_path_element_group_member_of_group(member_of, group))
        member_of = group
    entry.path.append(build_path_element_group_access_schema(groups[-1], schema, db_permissions))
    entry.path.append(build_path_element_table_member_of_schema(table, schema.name))
    return call(entry)


def build_identity_member_of_catalog_group_in_groups(
    identity: Identity,
    groups: List[Group],
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    catalog = table.get_catalog()
    schema = table.get_schema()
    entry = build_authz_entry_no_path(identity, table, permission_level)
    member_of = groups[0]
    for group in groups[1:]:
        entry.path.append(build_path_element_group_member_of_group(member_of, group))
        member_of = group
    entry.path.append(build_path_element_group_access_catalog(groups[-1], catalog, db_permissions))
    entry.path.append(build_path_element_schema_member_of_catalog(schema, catalog.name))
    entry.path.append(build_path_element_table_member_of_schema(table, schema.name))
    return call(entry)


def build_identity_member_of_group_schema_access(
    identity: Identity,
    group: Group,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    schema = table.get_schema()
    entry = build_authz_entry_no_path(identity, table, permission_level)
    entry.path = [
        build_path_element_group_access_schema(group, schema, db_permissions),
        build_path_element_table_member_of_schema(table, schema.name),
    ]
    return call(entry)


def build_identity_member_of_group_catalog_access(
    identity: Identity,
    group: Group,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    schema = table.get_schema()
    catalog = table.get_catalog()
    entry = build_authz_entry_no_path(identity, table, permission_level)
    entry.path = [
        # build_path_element_identity_member_of_group(identity, group),
        build_path_element_group_access_catalog(group, catalog, db_permissions),
        build_path_element_schema_member_of_catalog(schema, catalog.name),
        build_path_element_table_member_of_schema(table, schema.name),
    ]
    return call(entry)


def build_catalog_identity(
    identity: Identity,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    schema = table.get_schema()
    catalog = table.get_catalog()
    entry = build_authz_entry_no_path(identity, table, permission_level)
    entry.path = [
        build_identity_has_access_catalog(identity, catalog, db_permissions),
        build_path_element_schema_member_of_catalog(schema, catalog.name),
        build_path_element_table_member_of_schema(table, schema.name),
    ]
    return call(entry)


def build_schema_service_identity(
    identity: Identity,
    table: TestTable,
    permission_level: PermissionLevel,
    db_permissions: List[str],
):
    schema = table.get_schema()
    entry = build_authz_entry_no_path(identity, table, permission_level)
    entry.path = [
        build_path_element_identity_access_schema(identity, schema, db_permissions),
        build_path_element_table_member_of_schema(table, schema.name),
    ]
    return call(entry)


def build_path_element_identity_access_schema(identity: Identity, schema: TestSchema, db_permissions: List[str]):
    identity_element = build_path_element_schema_no_notes(schema)
    identity_element.db_permissions = db_permissions
    identity_element.notes = [
        build_note_identity_has_access_schema(identity, db_permissions, schema.get_schema_full_name())
    ]
    return identity_element


def build_path_element_group_access_schema(group: Group, schema: TestSchema, db_permissions: List[str]):
    element = build_path_element_group_name_no_notes(group)
    element.db_permissions = db_permissions
    element.notes = [build_note_group_has_access_schema(group, db_permissions, schema.get_schema_full_name())]
    return element


def build_path_element_group_access_table(group: Group, table: TestTable, db_permissions: List[str]):
    element = build_path_element_group_name_no_notes(group)
    element.db_permissions = db_permissions
    element.notes = [build_note_group_has_access_table(group, db_permissions, ".".join(table.get_full_name()))]
    return element


def build_path_element_group_access_catalog(group: Group, catalog: TestCatalog, db_permissions: List[str]):
    element = build_path_element_group_name_no_notes(group)
    element.db_permissions = db_permissions
    element.notes = [build_note_group_has_access_catalog(group, db_permissions, catalog.name)]
    return element


def build_path_element_table_member_of_schema(table: TestTable, schema_name: str):
    table_element = build_path_element_table_no_notes(table)
    table_element.notes = [build_note_member_of_table_schema(table.name, schema_name)]
    return table_element


def build_path_element_schema_member_of_catalog(schema: TestSchema, catalog_name: str):
    element = build_path_element_schema_no_notes(
        schema,
    )
    element.notes = [build_note_member_of_schema_catalog(schema.name, catalog_name)]
    return element


def build_identity_has_access_catalog(identity: Identity, catalog: TestCatalog, db_permissions: List[str]):
    return AuthzPathElement(
        id=catalog.name,
        name=catalog.name,
        type=AuthzPathElementType.CATALOG,
        notes=[
            build_note_identity_has_access_catalog(identity, db_permissions, catalog.name),
        ],
        db_permissions=db_permissions,
    )


def build_path_element_schema_no_notes(schema: TestSchema):
    return AuthzPathElement(
        id=schema.name,
        name=schema.name,
        type=AuthzPathElementType.SCHEMA,
        notes=[],
    )


def build_path_element_identity_no_notes(identity: Identity):
    return AuthzPathElement(
        id=identity.id,
        name=identity.name,
        type=IDENTITY_TYPE_TO_ELEMENT_TYPE[identity.type],
        notes=[],
    )


def build_path_element_table_no_notes(table: TestTable):
    return AuthzPathElement(
        id=table.name,
        name=table.name,
        type=AuthzPathElementType.TABLE,
        notes=[],
    )


def build_path_element_identity_member_of_group(identity: Identity, group: Group):
    element = build_path_element_group_no_notes(group)
    element.notes = [build_note_member_of(identity.name, "GROUP", group["displayName"])]
    return element


def build_path_element_group_member_of_group(member_group: Group, group: Group):
    element = build_path_element_group_name_no_notes(member_group)
    element.notes = [build_note_member_of(member_group["displayName"], "GROUP", group["displayName"])]
    return element


def build_path_element_group_no_notes(group: Group):
    return AuthzPathElement(
        id=group["id"],
        name=group["displayName"],
        type=AuthzPathElementType.GROUP,
        notes=[],
    )


def build_path_element_group_name_no_notes(group: Group):
    return AuthzPathElement(
        id=group["id"],
        name=group["displayName"],
        type=AuthzPathElementType.GROUP,
        notes=[],
    )


def build_authz_entry_no_path(
    identity: Identity,
    table: TestTable,
    permission_level: PermissionLevel,
):
    return AuthzEntry(
        identity=identity,
        asset=Asset(name=table.get_full_name(), type=AssetType.MANAGED),
        path=[],
        permission=permission_level,
    )


def build_identity_user(user: ParsedUser):
    return Identity(
        id=user["id"],
        name=user["userName"],
        type=IdentityType.USER,
    )


def build_identity_service_principal(service_principal: ServicePrincipal):
    return Identity(
        id=service_principal["applicationId"],
        name=service_principal["displayName"],
        type=IdentityType.SERVICE_PRINCIPAL,
    )


def build_note_identity_has_access_catalog(identity: Identity, db_permissions: List[str], name: str):
    return build_note_identity_has_access(identity, db_permissions, "CATALOG", name)


def build_note_identity_has_access_schema(identity: Identity, db_permissions: List[str], name: str):
    return build_note_identity_has_access(identity, db_permissions, "SCHEMA", name)


def build_note_identity_has_access_table(identity: Identity, db_permissions: List[str], name: str):
    return build_note_identity_has_access(identity, db_permissions, "TABLE", name)


def build_note_group_has_access_catalog(group: Group, db_permissions: List[str], name: str):
    return build_note_group_has_access(group, db_permissions, "CATALOG", name)


def build_note_group_has_access_schema(group: Group, db_permissions: List[str], name: str):
    return build_note_group_has_access(group, db_permissions, "SCHEMA", name)


def build_note_group_has_access_table(group: Group, db_permissions: List[str], name: str):
    return build_note_group_has_access(group, db_permissions, "TABLE", name)


def build_note_group_has_access(group: Group, db_permissions: List[str], asset_type: str, name: str):
    return build_note(
        f"GROUP {group['displayName']} has {','.join(db_permissions)} permissions for {asset_type} {name}"
    )


def build_note_identity_has_access(identity: Identity, db_permissions: List[str], asset_type: str, name: str):
    return build_note(
        f"{identity.type} {identity.name} has {','.join(db_permissions)} permissions for {asset_type} {name}"
    )


def build_note_member_of_schema_catalog(schema_name: str, catalog_name: str):
    return build_note_member_of(schema_name, "CATALOG", catalog_name)


def build_note_member_of_table_schema(table_name: str, schema_name: str):
    return build_note_member_of(table_name, "SCHEMA", schema_name)


def build_note_member_of(member_of: str, member_of_type: str, name: str):
    return build_note(f"{member_of} is member of {member_of_type} {name}")


def build_note(note: str):
    return AuthzNote(
        type=AuthzNoteType.GENERIC,
        note=note,
    )


IDENTITY_TYPE_TO_ELEMENT_TYPE = {
    IdentityType.USER: AuthzPathElementType.USER,
    IdentityType.SERVICE_PRINCIPAL: AuthzPathElementType.SERVICE_PRINCIPAL,
}
