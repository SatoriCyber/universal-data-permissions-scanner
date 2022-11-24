import csv
from pathlib import Path

from authz_data_model.authz_data_model import AuthorizationModel, DBRole, TableGrant


def _iter_rows_grants(name: str, grants: set[TableGrant]):
    for grant in grants:
        yield {name, grant.name, str(grant.permission_level)}


def _iter_role_row(user_name: str, role: DBRole, prev_roles: set[DBRole]):
    for grant in role.grants:
        str_prev_roles = "->".join({role.name for role in prev_roles})
        str_roles = role.name + "->" + str_prev_roles
        yield {user_name, grant.name, str_roles}
    
    for granted_role in role.roles:
        prev_roles.add(role)
        _iter_role_row(user_name=user_name, role=granted_role, prev_roles=prev_roles)

def export(model: AuthorizationModel, path: Path):
    with open(path, 'x', encoding="utf=8") as csv_file:
        csv_writer = csv.writer(csv_file, dialect="excel", escapechar="\\", strict=True)
        csv_writer.writerow({"user", "resource", "permission", "granted_by", "granted_at"})
        for user in model.user_grants.values():
            for row_to_write in _iter_rows_grants(user.name, user.grants):
                csv_writer.writerow(row_to_write)
            
            for role in user.roles:
                for role_row in _iter_role_row(user.name, role=role, prev_roles=set()):
                    csv_writer.writerow(role_row)

