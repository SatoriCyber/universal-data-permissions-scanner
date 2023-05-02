from typing import Dict, Generator, List, Set

from universal_data_permissions_scanner.datastores.postgres.model import AuthorizationModel, DBRole, ResourceGrant
from universal_data_permissions_scanner.models.model import (
    Asset,
    AuthzEntry,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
)
from universal_data_permissions_scanner.writers import BaseWriter


def _yield_row(role_name: str, grant: ResourceGrant, roles: List[DBRole]):
    auth_path_element = [
        AuthzPathElement(
            id=role.name,
            name=role.name,
            type=AuthzPathElementType.ROLE,
        )
        for role in roles
    ]
    auth_path_element[-1].db_permissions = grant.db_permissions
    identity = Identity(id=role_name, name=role_name, type=IdentityType.ROLE_LOGIN)
    asset = Asset(name=grant.name, type=grant.type)
    yield AuthzEntry(
        identity=identity,
        asset=asset,
        path=auth_path_element,
        permission=grant.permission_level,
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
        yield from _yield_row(role_name=base_role_name, grant=grant, roles=prev_roles)

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
                for entry in _yield_row(role_name=role.name, grant=grant, roles=[role]):
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
