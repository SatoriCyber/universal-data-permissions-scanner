from typing import Dict, Generator, List, Set

from universal_data_permissions_scanner.datastores.snowflake.model import (
    AuthorizationModel,
    DataShare,
    DataSharePrivilege,
    DBRole,
    PermissionType,
    ResourceGrant,
    User,
)
from universal_data_permissions_scanner.models import PermissionLevel
from universal_data_permissions_scanner.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
)
from universal_data_permissions_scanner.writers import BaseWriter


def _yield_row(
    identity: Identity, permission_level: PermissionLevel, grant: ResourceGrant, authz_path: List[AuthzPathElement]
):
    _add_db_permission_last_element(authz_path, grant.db_permissions)
    try:
        asset_type = AssetType(str(grant.granted_on))  # translate to AssetType
    except ValueError:
        asset_type = AssetType.TABLE  # set to table if not found
    asset = Asset(name=grant.name, type=asset_type)
    yield AuthzEntry(
        identity=identity,
        asset=asset,
        path=authz_path,
        permission=permission_level,
    )


def _add_db_permission_last_element(auth_path_element: List[AuthzPathElement], db_permissions: List[PermissionType]):
    """Add db permission to the last authz path element.
    In Snowflake the last role in the path is the one which grants permissions to the resource.

    Args:
        auth_path_element (List[AuthzPathElement]): Path of roles from the user to the resource.
        db_permission (str): the original db permission, e.g. "SELECT", "INSERT", etc.
    """
    auth_path_element[-1].db_permissions = [db_permission.value for db_permission in db_permissions]


def _iter_role_row(
    user_name: User,
    role: DBRole,
    prev_roles: List[DBRole],
    roles_to_grants: Dict[str, Set[ResourceGrant]],
    role_to_roles: Dict[str, Set[DBRole]],
) -> Generator[AuthzEntry, None, None]:
    grants = roles_to_grants.get(role.name, set())
    prev_roles.append(role)
    for grant in grants:
        identity = Identity(id=user_name.id, name=user_name.name, type=IdentityType.USER)
        authz_path = [
            AuthzPathElement(id=role.name, name=role.name, type=AuthzPathElementType.ROLE) for role in prev_roles
        ]
        yield from _yield_row(
            identity=identity, permission_level=grant.permission_level, grant=grant, authz_path=authz_path
        )

    for granted_role in role_to_roles.get(role.name, set()):
        yield from _iter_role_row(
            user_name=user_name,
            role=granted_role,
            prev_roles=prev_roles,
            roles_to_grants=roles_to_grants,
            role_to_roles=role_to_roles,
        )
    prev_roles.remove(role)


def _yield_share_with_db_role(
    identity: Identity,
    authz_path: List[AuthzPathElement],
    share: DataShare,
    role: DBRole,
    roles_to_grants: Dict[str, Set[ResourceGrant]],
    role_to_roles: Dict[str, Set[DBRole]],
    prev_roles: List[DBRole],
) -> Generator[AuthzEntry, None, None]:
    grants = roles_to_grants.get(role.name, set())
    prev_roles.append(role)
    for grant in grants:
        authz_path.extend(
            [AuthzPathElement(id=role.name, name=role.name, type=AuthzPathElementType.ROLE) for role in prev_roles]
        )
        yield from _yield_row(
            identity=identity, permission_level=grant.permission_level, grant=grant, authz_path=authz_path
        )

    for granted_role in role_to_roles.get(role.name, set()):
        yield from _yield_share_with_db_role(
            identity,
            authz_path,
            share=share,
            role=granted_role,
            prev_roles=prev_roles,
            roles_to_grants=roles_to_grants,
            role_to_roles=role_to_roles,
        )
    prev_roles.remove(role)


def _yield_share_with_direct_permissions(
    authz_path: List[AuthzPathElement],
    priv: DataSharePrivilege,
    identity: Identity,
    permission_level: PermissionLevel,
    db_permissions: Set[PermissionType],
):
    grant = ResourceGrant(
        name=priv.resource_name,
        permission_level=permission_level,
        db_permissions=list(db_permissions),
        granted_on=priv.granted_on,
    )
    yield from _yield_row(identity=identity, permission_level=permission_level, grant=grant, authz_path=authz_path)


def _yield_share(
    share: DataShare, roles_to_grants: Dict[str, Set[ResourceGrant]], role_to_roles: Dict[str, Set[DBRole]]
):
    authz_path = [
        AuthzPathElement(id=share.id, name=share.name, type=AuthzPathElementType.SHARE),
    ]
    for account in share.share_to_accounts:
        identity = Identity(id=account, name=account, type=IdentityType.ACCOUNT)
        for permission_level, permission in share.resources.items():
            for datashare_priv, db_permissions in permission.items():
                yield from _yield_share_with_direct_permissions(
                    authz_path, datashare_priv, identity, permission_level, db_permissions
                )
        for role in share.roles:
            yield from _yield_share_with_db_role(identity, authz_path, share, role, roles_to_grants, role_to_roles, [])


def export(model: AuthorizationModel, writer: BaseWriter):
    """Export the model to the writer."""
    for username, roles in model.users_to_roles.items():
        for role in roles:
            for entry in _iter_role_row(
                username,
                role=role,
                prev_roles=[],
                roles_to_grants=model.roles_to_grants,
                role_to_roles=model.role_to_roles,
            ):
                writer.write_entry(entry)
    for share in model.shares:
        for entry in _yield_share(share, model.roles_to_grants, model.role_to_roles):
            writer.write_entry(entry)
