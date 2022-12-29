from typing import Dict, Generator, List, Set

from authz_analyzer.datastores.redshift.model import AuthorizationModel, DBIdentity, IdentityId
from authz_analyzer.datastores.redshift.model import IdentityType as IdentityModelType
from authz_analyzer.datastores.redshift.model import ResourcePermission
from authz_analyzer.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)
from authz_analyzer.writers import BaseWriter

IDENTITY_TYPE_MODEL_TO_OUTPUT = {
    IdentityModelType.USER.name: IdentityType.USER,
    IdentityModelType.GROUP.name: IdentityType.GROUP,
    IdentityModelType.ROLE.name: IdentityType.ROLE,
}

# TODO AuthzPathElementType should be merged into model.IdentityType
IDENTITY_TYPE_MODEL_TO_AuthzPathElementType = {
    IdentityModelType.USER.name: AuthzPathElementType.USER,
    IdentityModelType.GROUP.name: AuthzPathElementType.GROUP,
    IdentityModelType.ROLE.name: AuthzPathElementType.ROLE,
}


def _yield_row(identity: DBIdentity, permission_level: PermissionLevel, grant_name: str, relations: List[DBIdentity]):
    auth_path_element = [
        AuthzPathElement(
            id=path_identity.id_,
            name=path_identity.name,
            type=IDENTITY_TYPE_MODEL_TO_AuthzPathElementType.get(path_identity.type_),
            note="",
        )
        for path_identity in relations
    ]
    identity = Identity(id=identity.id_, name=identity.name, type=IDENTITY_TYPE_MODEL_TO_OUTPUT.get(identity.type_))
    asset = Asset(name=grant_name, type=AssetType.TABLE)
    yield AuthzEntry(
        identity=identity,
        asset=asset,
        path=auth_path_element,
        permission=permission_level,
    )


def _iter_role_row(
    identity: DBIdentity,
    granted_identity: DBIdentity,
    prev_roles: List[DBIdentity],
    roles_to_grants: Dict[IdentityId, Set[ResourcePermission]],
    role_to_roles: Dict[DBIdentity, Set[DBIdentity]],
) -> Generator[AuthzEntry, None, None]:
    grants = roles_to_grants.get(granted_identity.id_, set())
    prev_roles.append(granted_identity)
    for grant in grants:
        yield from _yield_row(
            identity=identity, permission_level=grant.permission_level, grant_name=grant.name, relations=prev_roles
        )

    for nested_granted_identity in role_to_roles.get(granted_identity, set()):
        yield from _iter_role_row(
            identity=identity,
            granted_identity=nested_granted_identity,
            prev_roles=prev_roles,
            roles_to_grants=roles_to_grants,
            role_to_roles=role_to_roles,
        )
    prev_roles.remove(granted_identity)


def export(model: AuthorizationModel, writer: BaseWriter):
    """Export the model to the writer.

    Args:
        model (AuthorizationModel): Redshift model which describes the authorization
        writer (BaseWriter): Write to write the entries
    """
    for role, roles in model.identity_to_identities.items():
        if role.type_ == "USER":
            for grant in model.identity_to_resource_privilege.get(role.id_, set()):
                for entry in _yield_row(
                    identity=role, permission_level=grant.permission_level, grant_name=grant.name, relations=[role]
                ):
                    writer.write_entry(entry)

            for granted_role in roles:
                for entry in _iter_role_row(
                    identity=role,
                    granted_identity=granted_role,
                    prev_roles=[],
                    roles_to_grants=model.identity_to_resource_privilege,
                    role_to_roles=model.identity_to_identities,
                ):
                    writer.write_entry(entry)
