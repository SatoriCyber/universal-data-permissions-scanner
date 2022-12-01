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
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import snowflake.connector
from snowflake.connector.cursor import SnowflakeCursor

from authz_analyzer.datastores.base import BaseAuthzAnalyzer
from authz_analyzer.datastores.snowflake import exporter
from authz_analyzer.datastores.snowflake.model import (
    AuthorizationModel,
    DBRole,
    ResourceGrant,
    permission_level_from_str,
)
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE

COMMANDS_DIR = Path(__file__).parent / "commands"


@dataclass
class SnowflakeAuthzAnalyzer(BaseAuthzAnalyzer):
    cursor: SnowflakeCursor
    writer: BaseWriter
    logger: Logger

    @classmethod
    def connect(
        cls,
        host: str,
        account: str,
        username: str,
        password: str,
        warehouse: str,
        logger: Optional[Logger] = None,
        output_format: OutputFormat = OutputFormat.Csv,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
        **snowflake_connection_kwargs: Any,
    ):
        if logger is None:
            logger = get_logger(False)

        writer = get_writer(filename=output_path, format=output_format)

        connector = snowflake.connector.connect(  # type: ignore
            user=username,
            password=password,
            host=host,
            account=account,
            warehouse=warehouse,
            **snowflake_connection_kwargs,
        )
        cursor = connector.cursor()
        return cls(cursor=cursor, logger=logger, writer=writer)

    def run(
        self,
    ):
        self.logger.info("Starting to  query")
        authorization_model = self._get_authorization_model()
        self.logger.info("Starting to Analyze")
        exporter.export(model=authorization_model, writer=self.writer)
        self.logger.info("Finished analyzing")
        self.writer.close()

    def _get_users_to_role_mapping(self):
        command = (COMMANDS_DIR / "user_grants.sql").read_text(encoding="utf-8")
        rows: List[Tuple[str, str]] = self._get_rows(command=command)

        results: Dict[str, Set[DBRole]] = {}

        for row in rows:
            user_name: str = row[0]
            role_name = row[1]

            roles = results.setdefault(user_name, set())
            role = DBRole.new(name=role_name)
            roles.add(role)
        return results

    def _get_role_to_role_mapping(self):
        command = (COMMANDS_DIR / "roles_grants.sql").read_text(encoding="utf-8")
        rows: List[Tuple[str, str]] = self._get_rows(command=command)
        roles_grants_map: Dict[str, Set[DBRole]] = {}
        for row in rows:
            role_name = row[0]
            granted_role_name = row[1]

            role = roles_grants_map.setdefault(role_name, set())
            granted_role = DBRole.new(name=granted_role_name)
            role.add(granted_role)
        return roles_grants_map

    def _get_grants_to_role(self) -> Dict[str, Set[ResourceGrant]]:
        command = (COMMANDS_DIR / "roles_tables_resources.sql").read_text(encoding="utf-8")
        rows: List[Tuple[str, str, str]] = self._get_rows(command=command)  # type: ignore
        results: Dict[str, Set[ResourceGrant]] = {}

        for row in rows:
            role_name = row[0]
            table_name = row[2]

            level = permission_level_from_str(row[1])

            role_grants = results.setdefault(role_name, set())
            role_grants.add(ResourceGrant(table_name, level))
        return results

    def _get_authorization_model(self):
        self.logger.info("Fetching users to roles grants")
        users_to_roles = self._get_users_to_role_mapping()

        self.logger.info("Fetching roles to roles grants")
        role_to_roles = self._get_role_to_role_mapping()

        self.logger.info("Fetching roles to tables grants")
        roles_to_grants = self._get_grants_to_role()

        return AuthorizationModel(
            users_to_roles=users_to_roles, role_to_roles=role_to_roles, roles_to_grants=roles_to_grants
        )

    def _get_rows(self, command: str) -> List[Tuple[Any, ...]]:
        self.cursor.execute(command)
        return self.cursor.fetchall()  # type: ignore
