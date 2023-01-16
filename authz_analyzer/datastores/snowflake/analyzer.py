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

from authz_analyzer.datastores.snowflake import exporter
from authz_analyzer.datastores.snowflake.model import (
    PERMISSION_LEVEL_MAP,
    AuthorizationModel,
    DBRole,
    GrantedOn,
    ResourceGrant,
    User,
)
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE

COMMANDS_DIR = Path(__file__).parent / "commands"


@dataclass
class SnowflakeAuthzAnalyzer:
    """Analyze authorization for Snowflake."""

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
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
        **snowflake_connection_kwargs: Any,
    ):
        """Connect to Snowflake and return an analyzer.

        Args:
            host (str): Snowflake host
            account (str): Snowflake account
            username (str): Snowflake username to connect with
            password (str): Snowflake password to connect with
            warehouse (str): Snowflake warehouse to use
            logger (Optional[Logger], optional): Python logger. Defaults to None.
            output_path (Union[Path, str], optional): Path to write the file. Defaults to ./authz-analyzer-export.
            output_format (OutputFormat, optional): Output format. Defaults to OutputFormat.CSV.
        """
        if logger is None:
            logger = get_logger(False)

        writer = get_writer(filename=output_path, output_format=output_format)

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
        """Run the analyzer."""
        self.logger.info("Starting to  query")
        authorization_model = self._get_authorization_model()
        self.logger.info("Starting to Analyze")
        exporter.export(model=authorization_model, writer=self.writer)
        self.logger.info("Finished analyzing")
        self.writer.close()

    def _get_users_to_role_mapping(self):
        rows: List[Tuple[str, str, Optional[str]]] = self._get_rows(file_name_command=Path("user_grants.sql"))

        results: Dict[User, Set[DBRole]] = {}

        for row in rows:
            user_name: str = row[0]
            role_name = row[1]
            # row[2] is usually the email. if if it none then user_id will just be the name
            user_id = row[2]
            if user_id is None:
                user_id = user_name
            user = User(name=user_name, id=user_id)

            roles = results.setdefault(user, set())
            if role_name is not None:
                role = DBRole.new(name=role_name, roles=set())
                roles.add(role)
            roles.add(DBRole(name="PUBLIC", roles=set()))
        return results

    @staticmethod
    def _add_role_to_roles(role_name: str, granted_role_name: str, role_to_roles: Dict[str, Set[DBRole]]):
        role = role_to_roles.setdefault(role_name, set())
        granted_role = DBRole.new(name=granted_role_name, roles=set())
        role.add(granted_role)

    @staticmethod
    def _add_role_to_resources(
        role_name: str,
        table_name: List[str],
        database_level: str,
        role_to_resources: Dict[str, Set[ResourceGrant]],
        granted_on: GrantedOn,
    ):
        level = PERMISSION_LEVEL_MAP[database_level]
        role_grants = role_to_resources.setdefault(role_name, set())
        role_grants.add(ResourceGrant(table_name, level, database_level, granted_on=granted_on))

    def _get_role_to_roles_and_role_to_resources(self) -> Tuple[Dict[str, Set[DBRole]], Dict[str, Set[ResourceGrant]]]:
        rows = self._get_rows(file_name_command=Path("grants_roles.sql"))
        role_to_roles: Dict[str, Set[DBRole]] = {}
        role_to_resources: Dict[str, Set[ResourceGrant]] = {}

        for row in rows:
            name: str = row[0]
            role: str = row[1]
            privilege: str = row[2]
            db: str = row[3]
            schema: str = row[4]
            table: str = row[5]
            granted_on = GrantedOn.from_str(row[6])

            if privilege == "USAGE" and granted_on == GrantedOn.ROLE:
                SnowflakeAuthzAnalyzer._add_role_to_roles(role, name, role_to_roles)
            elif table is not None and granted_on in (GrantedOn.TABLE, GrantedOn.VIEW, GrantedOn.MATERIALIZED_VIEW):
                SnowflakeAuthzAnalyzer._add_role_to_resources(
                    role_name=role,
                    database_level=privilege,
                    table_name=[db, schema, table],
                    role_to_resources=role_to_resources,
                    granted_on=granted_on,
                )
        return role_to_roles, role_to_resources

    def _get_authorization_model(self):
        self.logger.info("Fetching users to roles grants")
        users_to_roles = self._get_users_to_role_mapping()
        role_to_roles, roles_to_grants = self._get_role_to_roles_and_role_to_resources()

        return AuthorizationModel(
            users_to_roles=users_to_roles, role_to_roles=role_to_roles, roles_to_grants=roles_to_grants
        )

    def _get_rows(self, file_name_command: Path) -> List[Tuple[Any, ...]]:
        command = (COMMANDS_DIR / file_name_command).read_text(encoding="utf-8")
        self.cursor.execute(command)
        return self.cursor.fetchall()  # type: ignore
