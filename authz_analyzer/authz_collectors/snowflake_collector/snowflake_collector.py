from dataclasses import dataclass
from pathlib import Path
from typing import Any

from authz_data_model.authz_data_model import (
    AuthorizationModel,
    DBRole,
    DBUser,
    PermissionLevel,
    TableGrant,
)
from utils.connectors.snowflake_connector.snowflake_connector import AuthZSnowflakeConnector

COMMANDS_DIR = Path(__file__).parent / "commands"


@dataclass
class AuthZSnowflakeCollector:
    connector: AuthZSnowflakeConnector

    @classmethod
    def connect(cls, host: str, username: str, password: str, **kwargs: Any):
        print("Connecting to Snowflake")
        return cls(connector=AuthZSnowflakeConnector.connect(host, username, password, **kwargs))
    
    def _get_users_to_role_mapping(self):
        command = (COMMANDS_DIR / "user_grants.sql").read_text(encoding="utf-8")
        rows: list[tuple[str, str]] = self.connector.execute(command=command)  # type: ignore

        results: dict[str, DBUser] = {}

        for row in rows:
            user_name: str = row[0]
            role_name = row[1]

            user = results.setdefault(user_name, DBUser.new(name=user_name))
            role = DBRole.new(name=role_name)
            user.add_role(role)
        return results

    def _get_role_to_role_mapping(self):
        command = (COMMANDS_DIR / "roles_grants.sql").read_text(encoding="utf-8")
        rows: list[tuple[str, str]] = self.connector.execute(command=command)  # type: ignore
        roles_grants_map: dict[str, DBRole] = {}
        for row in rows:
            role_name = row[0]
            granted_role_name = row[1]

            role = roles_grants_map.setdefault(role_name, DBRole.new(name=role_name))
            granted_role = DBRole.new(name=granted_role_name)
            role.add_role(granted_role)
        return roles_grants_map

    def _add_table_grants_to_role(self, roles_grants_map: dict[str, DBRole]):
        command = (COMMANDS_DIR / "roles_tables_resources.sql").read_text(encoding="utf-8")
        rows: list[tuple[str, str, str]] = self.connector.execute(command=command)  # type: ignore
        for row in rows:
            role_name = row[0]
            level = PermissionLevel.from_str(row[1])
            table_name = row[2]
            
            roles_grants_map[role_name].add_grant(TableGrant(name=table_name, permission_level=level))
        

    def get_authorization_model(self) -> AuthorizationModel:
        print("Fetching users to roles grants")
        user_grants = self._get_users_to_role_mapping()
        print("Fetching roles to roles grants")
        roles_grants = self._get_role_to_role_mapping()
        print("Fetching roles to tables grants")
        self._add_table_grants_to_role(roles_grants)
        print("Done fetching")
        return AuthorizationModel(user_grants=user_grants, roles_grants=roles_grants)
