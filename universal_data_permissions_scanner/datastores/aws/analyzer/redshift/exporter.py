from typing import Dict, Generator, List, Set

from universal_data_permissions_scanner.datastores.aws.analyzer.redshift.model import (
    AuthorizationModel,
    DBIdentity,
    IdentityId,
)
from universal_data_permissions_scanner.datastores.aws.analyzer.redshift.model import IdentityType as IdentityModelType
from universal_data_permissions_scanner.datastores.aws.analyzer.redshift.model import ResourcePermission, Share
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
from universal_data_permissions_scanner.writers import BaseWriter

IDENTITY_TYPE_MODEL_TO_OUTPUT = {
    IdentityModelType.USER: IdentityType.USER,
    IdentityModelType.GROUP: IdentityType.GROUP,
    IdentityModelType.ROLE: IdentityType.ROLE,
}


IDENTITY_TYPE_MODEL_TO_AuthzPathElementType = {
    IdentityModelType.USER: AuthzPathElementType.USER,
    IdentityModelType.GROUP: AuthzPathElementType.GROUP,
    IdentityModelType.ROLE: AuthzPathElementType.ROLE,
}


def _yield_row(
    identity: DBIdentity,
    permission_level: PermissionLevel,
    grant_name: List[str],
    relations: List[DBIdentity],
    db_permissions: List[str],
):
    notes = [
        AuthzNote(
            note="",
            type=AuthzNoteType.GENERIC,
        )
    ]
    auth_path_element = [
        AuthzPathElement(
            id=str(path_identity.id_),
            name=path_identity.name,
            type=IDENTITY_TYPE_MODEL_TO_AuthzPathElementType[path_identity.type],
            notes=notes,
        )
        for path_identity in relations
    ]
    auth_path_element[-1].db_permissions = db_permissions
    model_identity = Identity(
        id=str(identity.id_), name=identity.name, type=IDENTITY_TYPE_MODEL_TO_OUTPUT[identity.type]
    )
    asset = Asset(name=grant_name, type=AssetType.TABLE)
    yield AuthzEntry(
        identity=model_identity,
        asset=asset,
        path=auth_path_element,
        permission=permission_level,
    )


def _iter_role_row(
    identity: DBIdentity,
    granted_identity: DBIdentity,
    prev_roles: List[DBIdentity],
    roles_to_grants: Dict[IdentityId, Dict[str, Set[ResourcePermission]]],
    role_to_roles: Dict[DBIdentity, Set[DBIdentity]],
) -> Generator[AuthzEntry, None, None]:
    prev_roles.append(granted_identity)
    for grants in roles_to_grants.get(granted_identity.id_, {}).values():
        for grant in grants:
            yield from _yield_row(
                identity=identity,
                permission_level=grant.permission_level,
                grant_name=grant.name,
                relations=prev_roles,
                db_permissions=grant.db_permissions,
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


def _iter_datashare_row(share: Share):
    consumer = ""
    if share.consumer_account_id is not None:
        consumer = share.consumer_account_id + "_"
    consumer += share.consumer_namespace
    identity = Identity(
        id=consumer,
        type=IdentityType.CLUSTER,
        name=consumer,
    )
    path = [AuthzPathElement(id=share.id, name=share.name, type=AuthzPathElementType.SHARE, db_permissions=[])]
    for resource in share.resources:
        notes = [
            AuthzNote(
                note=f"share {share.name} grants access to account {share.consumer_account_id} in the following namespace {share.consumer_namespace}",
                type=AuthzNoteType.GENERIC,
            )
        ]
        path[0].notes = notes
        yield AuthzEntry(
            identity=identity,
            asset=Asset(name=resource.name, type=AssetType.TABLE),
            path=path,
            permission=PermissionLevel.READ,
        )


def export(model: AuthorizationModel, writer: BaseWriter):
    """Export the model to the writer.

    Args:
        model (AuthorizationModel): Redshift model which describes the authorization
        writer (BaseWriter): Write to write the entries
    """
    for role, roles in model.identity_to_identities.items():
        if role.type is IdentityModelType.USER:
            for grants in model.identity_to_resource_privilege.get(role.id_, {}).values():
                for grant in grants:
                    for entry in _yield_row(
                        identity=role,
                        permission_level=grant.permission_level,
                        grant_name=grant.name,
                        relations=[role],
                        db_permissions=grant.db_permissions,
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

    for datashare in model.data_shares:
        for entry in _iter_datashare_row(datashare):
            writer.write_entry(entry)
