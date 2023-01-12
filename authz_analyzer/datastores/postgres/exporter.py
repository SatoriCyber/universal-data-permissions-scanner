from typing import Dict, Generator, List, Set

from authz_analyzer.datastores.postgres.model import AuthorizationModel, DBRole, ResourceGrant
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


def _yield_row(role_name: str, permission_level: PermissionLevel, grant_name: str, roles: List[DBRole]):
    auth_path_element = [
        AuthzPathElement(id=role.name, name=role.name, type=AuthzPathElementType.ROLE, note="") for role in roles
    ]
    identity = Identity(id=role_name, name=role_name, type=IdentityType.ROLE_LOGIN)
    asset = Asset(name=grant_name, type=AssetType.TABLE)
    yield AuthzEntry(
        identity=identity,
        asset=asset,
        path=auth_path_element,
        permission=permission_level,
        db_permissions=[roles[-1].name],
    )


def _iter_role_row(
    base_role_name: str,
    role: DBRole,
    prev_roles: List[DBRole],
    roles_to_grants: Dict[str, Set[ResourceGrant]],
    role_to_roles: Dict[DBRole, Set[DBRole]],
) -> Generator[AuthzEntry, None, None]:
    grants = roles_to_grants.get(role.name, set())
    prev_roles.append(role)
    for grant in grants:
        yield from _yield_row(
            role_name=base_role_name, permission_level=grant.permission_level, grant_name=grant.name, roles=prev_roles
        )

    for granted_role in role_to_roles.get(role, set()):
        yield from _iter_role_row(
            base_role_name=base_role_name,
            role=granted_role,
            prev_roles=prev_roles,
            roles_to_grants=roles_to_grants,
            role_to_roles=role_to_roles,
        )
    prev_roles.remove(role)


def export(model: AuthorizationModel, writer: BaseWriter):
    """Export the model to the writer.

    Args:
        model (AuthorizationModel): Postgres model which describes the authorization
        writer (BaseWriter): Write to write the entries
    """
    for role, roles in model.role_to_roles.items():
        if role.can_login is True:
            for grant in model.role_to_grants.get(role.name, set()):
                for entry in _yield_row(
                    role_name=role.name, permission_level=grant.permission_level, grant_name=grant.name, roles=[role]
                ):
                    writer.write_entry(entry)

            for granted_role in roles:
                for entry in _iter_role_row(
                    role.name,
                    role=granted_role,
                    prev_roles=[],
                    roles_to_grants=model.role_to_grants,
                    role_to_roles=model.role_to_roles,
                ):
                    writer.write_entry(entry)
