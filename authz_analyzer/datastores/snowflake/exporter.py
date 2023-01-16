from typing import Dict, Generator, List, Set

from authz_analyzer.datastores.snowflake.model import AuthorizationModel, DBRole, ResourceGrant, User
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

USER_TYPE = IdentityType.USER
ASSET_TYPE = AssetType.TABLE


def _yield_row(user: User, permission_level: PermissionLevel, grant: ResourceGrant, roles: List[DBRole]):
    auth_path_element = [
        AuthzPathElement(id=role.name, name=role.name, type=AuthzPathElementType.ROLE, note="") for role in roles
    ]
    _add_db_permission_last_element(auth_path_element, grant.db_permission)
    identity = Identity(id=user.id, name=user.name, type=USER_TYPE)
    try:
        asset_type = AssetType(str(grant.granted_on))  # translate to AssetType
    except ValueError:
        asset_type = AssetType.TABLE  # set to table if not found
    asset = Asset(name=grant.name, type=asset_type)
    yield AuthzEntry(
        identity=identity,
        asset=asset,
        path=auth_path_element,
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
        yield from _yield_row(user=user_name, permission_level=grant.permission_level, grant=grant, roles=prev_roles)

    for granted_role in role_to_roles.get(role.name, set()):
        yield from _iter_role_row(
            user_name=user_name,
            role=granted_role,
            prev_roles=prev_roles,
            roles_to_grants=roles_to_grants,
            role_to_roles=role_to_roles,
        )
    prev_roles.remove(role)


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
