"""Analyze authorization for Postgres.

Postgres both users and groups are roles.
Roles can be members of other roles.
In order to bootstrap the database system, a freshly initialized system always contains one predefined role. 
This role is always a "superuser".
 
Attributes:
Login:
Only roles that have the LOGIN attribute can be used as the initial role name for a database connection. 
A role with the LOGIN attribute can be considered the same as a “database user”

The database will not let you set up circular membership loops.
"""

from ast import Tuple
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Any, Dict, Optional, Set, Union

import psycopg2
from psycopg2.extensions import cursor, ISOLATION_LEVEL_AUTOCOMMIT

from authz_analyzer.datastores.base import BaseAuthzAnalyzer
from authz_analyzer.datastores.postgres import exporter
from authz_analyzer.datastores.postgres.model import (
    AuthorizationModel,
    DBRole,
    ResourceGrant,
    RoleName,
    permission_level_from_str,
)
from authz_analyzer.models.model import PermissionLevel
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE

COMMANDS_DIR = Path(__file__).parent / "commands"


@dataclass
class PostgresAuthzAnalyzer(BaseAuthzAnalyzer):
    cursor: cursor
    writer: BaseWriter
    logger: Logger

    @classmethod
    def connect(
        cls,
        username: str,
        password: str,
        host: str,
        dbname: str,
        logger: Optional[Logger] = None,
        output_format: OutputFormat = OutputFormat.Csv,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
        **connection_kwargs: Any,
    ):
        if logger is None:
            logger = get_logger(False)

        writer = get_writer(filename=output_path, format=output_format)
        connector: psycopg2.connection = psycopg2.connect(
            user=username, password=password, host=host, dbname=dbname, **connection_kwargs
        )
        connector.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)


        postgres_cursor = connector.cursor()
        return cls(logger=logger, cursor=postgres_cursor, writer=writer)

    def run(
        self,
    ):
        authorization_model = self._get_authorization_model()

        self.logger.info("Starting to Analyze")
        exporter.export(model=authorization_model, writer=self.writer)
        self.logger.info("Finished analyzing")
        self.writer.close()

    def _get_all_databases(self):
        return {database[0] for database in  self._get_rows("all_databases.sql")}
    
    def _get_authorization_model(self):
        all_databases: Set[str] = self._get_all_databases()
        self.logger.info("Fetching users to roles grants")
        role_to_roles = self._get_role_roles_mapping()

        self.logger.info("Fetching roles to tables grants")
        role_to_grants = self._get_roles_grants(all_databases)

        self._add_super_user(role_to_grants)

        return AuthorizationModel(role_to_roles=role_to_roles, role_to_grants=role_to_grants)

    def _get_role_roles_mapping(self):
        command = (COMMANDS_DIR / "roles.sql").read_text()

        rows = self._get_rows(command)
        results: Dict[DBRole, Set[DBRole]] = {}
        for row in rows:
            role_name: str = row[0]
            superuser = bool(row[1])
            granted_role_name: Optional[str] = row[2]
            can_login: bool = row[3]

            role = DBRole.new(name=role_name, roles=set(), can_login=can_login)

            role_grants = results.setdefault(role, set())
            if granted_role_name is not None:
                role_grants.add(DBRole.new(granted_role_name, set(), False))
            if superuser is True:
                role_grants.add(DBRole.new("super_user", set(), False))

        return results

    def _get_roles_grants(self, all_databases: Set[str]) -> Dict[RoleName, Set[ResourceGrant]]:
        command = (COMMANDS_DIR / "roles_grants.sql").read_text()
        rows = self._get_rows(command)
        results: Dict[RoleName, Set[ResourceGrant]] = {}
        for row in rows:
            _grantor = row[0]
            role = row[1]
            table_name = row[2]
            level = permission_level_from_str(row[3])

            role_grants = results.setdefault(role, set())
            role_grants.add(ResourceGrant(table_name, level))

        return results

    def _add_super_user(self, role_to_grants: Dict[RoleName, Set[ResourceGrant]]):
        self.logger.info("Fetching all tables")
        command = (COMMANDS_DIR / "all_tables.sql").read_text()
        rows = self._get_rows(command)

        all_tables = {ResourceGrant(table_name[0], PermissionLevel.Full) for table_name in rows}
        super_user_role = "super_user"
        role_to_grants[super_user_role] = all_tables

    def _get_rows(self, command: str, params: Optional[Set[Any]] = None):
        self.cursor.execute(command, params)
        return self.cursor.fetchall()

    def _prepare_statement(self, command: str):
        self.cursor.pr