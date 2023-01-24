from typing import Dict, Generator, List, Set

from authz_analyzer.datastores.snowflake.model import (
    AuthorizationModel,
    DataShare,
    DBRole,
    GrantedOn,
    PermissionType,
    ResourceGrant,
    User,
)
from authz_analyzer.models import PermissionLevel
from authz_analyzer.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
)
from authz_analyzer.writers import BaseWriter


def _yield_row(
    identity: Identity, permission_level: PermissionLevel, grant: ResourceGrant, authz_path: List[AuthzPathElement]
):
    _add_db_permission_last_element(authz_path, grant.db_permission.value)
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


def _add_db_permission_last_element(auth_path_element: List[AuthzPathElement], db_permission: str):
    """Add db permission to the last authz path element.
    In Snowflake the last role in the path is the one which grants permissions to the resource.

    Args:
        auth_path_element (List[AuthzPathElement]): Path of roles from the user to the resource.
        db_permission (str): the original db permission, e.g. "SELECT", "INSERT", etc.
    """
    auth_path_element[-1].db_permissions = [db_permission]


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
            AuthzPathElement(id=role.name, name=role.name, type=AuthzPathElementType.ROLE, note="")
            for role in prev_roles
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


def _yield_share(share: DataShare, write: BaseWriter):
    for account in share.share_to_accounts:
        identity = Identity(id=account, name=account, type=IdentityType.ACCOUNT)
        for priv in share.privileges:
            db_permission = PermissionType(priv.database_permission.value)
            granted_on = GrantedOn(priv.granted_on)
            grant = ResourceGrant(
                name=priv.resource_name,
                permission_level=priv.permission_level,
                db_permission=db_permission,
                granted_on=granted_on,
            )
            authz_path = [
                AuthzPathElement(id=".".join(share.id), name=share.name, type=AuthzPathElementType.SHARE, note=""),
            ]
            yield from _yield_row(
                identity=identity, permission_level=priv.permission_level, grant=grant, authz_path=authz_path
            )


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
        for entry in _yield_share(share, writer):
            writer.write_entry(entry)
