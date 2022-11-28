"""Analyze authorization for Snowflake.

Snowflake uses RBAC access control.
Users have roles.
roles can haves other roles (inherit)

roles have privileges on resources.

there is no super-user, even if a user has accountadmin it still
don't have access to read from all tables and need to be granted with this access.

The access to data is based on table/view etc', even if a user has ownership of a schema
or a database it doesn't have the privilege to query it.

future grants:
give the user privilege for new tables/views created in the database/schema.
doesn't change access to already created resources.

The analyzer query to tables: snowflake.account_usage.grants_to_users, snowflake.account_usage.grants_to_roles

"""

from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Dict, Set

from authz_analyzer.datastores.snowflake.connector import SnowflakeConnector
from authz_analyzer.datastores.snowflake.model import (
    AuthorizationModel,
    DBUser,
    DBRole,
    ResourceGrant,
    permission_level_from_str,
)
from authz_analyzer.datastores.snowflake import exporter
from authz_analyzer.datastores.base import BaseConnectParams
from authz_analyzer.writers import BaseWriter

COMMANDS_DIR = Path(__file__).parent / "commands"


@dataclass
class SnowflakeAuthzAnalyzer:
    logger: Logger
    connector: SnowflakeConnector
    writer: BaseWriter

    @classmethod
    def _load(cls, params: BaseConnectParams, writer: BaseWriter, logger: Logger):
        return cls(connector=SnowflakeConnector.connect(params), writer=writer, logger=logger)

    @staticmethod
    def run(params: BaseConnectParams, writer: BaseWriter, logger: Logger):
        logger.info("Connecting to Snowflake")
        snowflake_authz_analyzer = SnowflakeAuthzAnalyzer._load(params=params, writer=writer, logger=logger)
        logger.info("Starting to  query")
        authorization_model = snowflake_authz_analyzer._get_authorization_model()
        logger.info("Writing to file")
        exporter.export(model=authorization_model, writer=writer)

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
        roles_grants_map: dict[str, set[DBRole]] = {}
        for row in rows:
            role_name = row[0]
            granted_role_name = row[1]

            role = roles_grants_map.setdefault(role_name, set())
            granted_role = DBRole.new(name=granted_role_name)
            role.add(granted_role)
        return roles_grants_map

    # def _add_table_grants_to_role(self, roles_grants_map: dict[str, DBRole]):
    #     command = (COMMANDS_DIR / "roles_tables_resources.sql").read_text(encoding="utf-8")
    #     rows: list[tuple[str, str, str]] = self.connector.execute(command=command)  # type: ignore
    #     for row in rows:
    #         role_name = row[0]
    #         table_name = row[2]

    #         level = permission_level_from_str(row[1])

    #         try:
    #             roles_grants_map[role_name].add_grant(ResourceGrant(name=table_name, permission_level=level))
    #         except KeyError as err:
    #             self.logger.warn("Failed to add grant: {} {}", roles_grants_map, err)

    def _get_grants_to_role(self) -> Dict[str, Set[ResourceGrant]]:
        command = (COMMANDS_DIR / "roles_tables_resources.sql").read_text(encoding="utf-8")
        rows: list[tuple[str, str, str]] = self.connector.execute(command=command)  # type: ignore
        results: Dict[str, Set[ResourceGrant]] = {}

        for row in rows:
            role_name = row[0]
            table_name = row[2]

            level = permission_level_from_str(row[1])

            role_grants = results.setdefault(role_name, set())
            role_grants.add(ResourceGrant(table_name, level))
        return results

    # @staticmethod
    # def _set_roles_for_role(role: DBRole, roles_grants: Dict[str, DBRole], grants_roles: Dict[str, Set[ResourceGrant]]):
    #     extended_role = roles_grants.get(role.name)
    #     if extended_role is not None:
    #         for role_of_role in extended_role.roles:
    #             SnowflakeAuthzAnalyzer._set_roles_for_role(role_of_role, roles_grants, grants_roles)
    #         extended_role.grants = grants_roles.get(extended_role.name, set())
    #         role.add_role(extended_role)

    # @staticmethod
    # def _set_user_role(user: DBUser, role_to_roles: Dict[str, DBRole], grants_roles: Dict[str, Set[ResourceGrant]]):
    #     extended_roles: Set[DBRole] = set()
    #     for role in user.roles:
    #         role.grants = grants_roles.get(role.name, set())
    #         extended_roles.add(role)
    #         SnowflakeAuthzAnalyzer._set_roles_for_role(role, role_to_roles, grants_roles)
    #     user.roles = extended_roles

    # @staticmethod
    # def _build_authorization_model(
    #     user_grants: Dict[str, DBUser], role_to_roles: Dict[str, DBRole], grants_to_roles: Dict[str, Set[ResourceGrant]]
    # ):
    #     for user in user_grants.values():
    #         SnowflakeAuthzAnalyzer._set_user_role(user, role_to_roles, grants_to_roles)
    #     return user_grants

    def _get_authorization_model(self):
        self.logger.debug("Fetching users to roles grants")
        users_to_roles = self._get_users_to_role_mapping()

        self.logger.debug("Fetching roles to roles grants")
        role_to_roles = self._get_role_to_role_mapping()

        self.logger.debug("Fetching roles to tables grants")

        roles_to_grants = self._get_grants_to_role()

        return AuthorizationModel(users_to_roles=users_to_roles, role_to_roles=role_to_roles, roles_to_grants=roles_to_grants)
