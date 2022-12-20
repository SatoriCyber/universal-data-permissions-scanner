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


def _yield_row(user: User, permission_level: PermissionLevel, grant_name: str, roles: List[DBRole]):
    auth_path_element = [
        AuthzPathElement(id=role.name, name=role.name, type=AuthzPathElementType.ROLE, note="") for role in roles
    ]
    identity = Identity(id=user.id, name=user.name, type=USER_TYPE)
    asset = Asset(name=grant_name, type=ASSET_TYPE)
    yield AuthzEntry(
        identity=identity,
        asset=asset,
        path=auth_path_element,
        permission=permission_level,
    )


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
        yield from _yield_row(
            user=user_name, permission_level=grant.permission_level, grant_name=grant.name, roles=prev_roles
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
