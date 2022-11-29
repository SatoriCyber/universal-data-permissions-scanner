from typing import Dict, Generator, List, Set

from authz_analyzer.datastores.snowflake.model import AuthorizationModel, DBRole, ResourceGrant
from authz_analyzer.models import PermissionLevel
from authz_analyzer.models.model import AuthzEntry, AuthzPathElement
from authz_analyzer.writers import BaseWriter


def _yield_row(username: str, permission_level: PermissionLevel, grant_name: str, roles: str):
    auth_path_element = AuthzPathElement(id="", name=roles, type="", note="")
    yield AuthzEntry(
        identity=username,
        asset=grant_name,
        path=[auth_path_element],
        permission=permission_level,
    )


def _iter_role_row(
    user_name: str,
    role: DBRole,
    prev_roles: List[DBRole],
    roles_to_grants: Dict[str, Set[ResourceGrant]],
    role_to_roles: Dict[str, Set[DBRole]],
) -> Generator[AuthzEntry, None, None]:
    grants = roles_to_grants.get(role.name, set())
    for grant in grants:
        if len(prev_roles) == 0:
            yield from _yield_row(
                username=user_name, permission_level=grant.permission_level, grant_name=grant.name, roles=role.name
            )
        else:
            str_prev_roles = "->".join([role.name for role in prev_roles])
            str_roles = str_prev_roles + "->" + role.name
            yield from _yield_row(
                username=user_name, permission_level=grant.permission_level, grant_name=grant.name, roles=str_roles
            )

    for granted_role in role_to_roles.get(role.name, set()):
        prev_roles.append(role)
        yield from _iter_role_row(
            user_name=user_name,
            role=granted_role,
            prev_roles=prev_roles,
            roles_to_grants=roles_to_grants,
            role_to_roles=role_to_roles,
        )


def export(model: AuthorizationModel, writer: BaseWriter):
    for user in model.users_to_roles.values():
        for role in user.roles:
            for entry in _iter_role_row(
                user.name,
                role=role,
                prev_roles=[],
                roles_to_grants=model.roles_to_grants,
                role_to_roles=model.role_to_roles,
            ):
                writer.write_entry(entry)
