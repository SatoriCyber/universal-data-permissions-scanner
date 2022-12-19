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

from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT, cursor

from authz_analyzer.datastores.postgres import exporter
from authz_analyzer.datastores.postgres.model import (
    AuthorizationModel,
    DBRole,
    ResourceGrant,
    RoleName,
    PERMISSION_LEVEL_MAP
)
from authz_analyzer.models.model import PermissionLevel
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE

COMMANDS_DIR = Path(__file__).parent / "commands"


@dataclass
class PostgresAuthzAnalyzer:
    """Analyze authorization for Postgres."""
    cursors: List[cursor]
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
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
        **connection_kwargs: Any,
    ):
        """Connect to Postgres and return an analyzer.

        Args:
            username (str): Postgres username
            password (str): Postgres password
            host (str): Postgres host, can be a hostname or an IP address
            dbname (str): Postgres database name
            logger (Optional[Logger], optional): Python logger. Defaults to None.
            output_path (Union[Path, str], optional): Path to write the file. Defaults to ./authz-analyzer-export.
            credentials_str (Optional[str], optional): ServiceAccount to connect to BigQuery. Defaults to None.
        """
        if logger is None:
            logger = get_logger(False)

        writer = get_writer(filename=output_path, output_format=output_format)
        connector: psycopg2.connection = psycopg2.connect(  # pylint: disable=E1101:no-member
            user=username, password=password, host=host, dbname=dbname, **connection_kwargs
        )
        connector.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

        postgres_cursor = connector.cursor()

        # We generate cursor one per database in order to fetch the table grants and the information schema
        postgres_cursors: List[cursor] = []
        for database in PostgresAuthzAnalyzer._get_all_databases(postgres_cursor):
            if database == "rdsadmin":
                logger.debug("Skipping rdsadmin database, internal use by AWS")
                continue
            db_connector: psycopg2.connection = psycopg2.connect(  # pylint: disable=E1101:no-member
                user=username, password=password, host=host, dbname=database, **connection_kwargs
            )
            postgres_cursors.append(db_connector.cursor())
        return cls(logger=logger, cursors=postgres_cursors, writer=writer)

    def run(
        self,
    ):
        """Read all tables in all databases and calculate authz paths."""
        authorization_model = self._get_authorization_model()

        self.logger.info("Starting to Analyze")
        exporter.export(model=authorization_model, writer=self.writer)
        self.logger.info("Finished analyzing")
        self.writer.close()

    @staticmethod
    def _get_all_databases(postgres_cursor: cursor):
        return {
            database[0]
            for database in PostgresAuthzAnalyzer._get_rows(
                postgres_cursor, (COMMANDS_DIR / "all_databases.sql").read_text()
            )
        }

    def _get_authorization_model(self):
        self.logger.info("Fetching users to roles grants")
        role_to_roles = self._get_role_roles_mapping()

        self.logger.info("Fetching roles to tables grants")
        role_to_grants = self._get_roles_grants()

        self._add_super_user(role_to_grants)

        return AuthorizationModel(role_to_roles=role_to_roles, role_to_grants=role_to_grants)

    def _get_role_roles_mapping(self):
        command = (COMMANDS_DIR / "roles.sql").read_text()

        results: Dict[DBRole, Set[DBRole]] = {}

        # For roles table, it is shared per cluster, there is no need to pull per DB
        pg_cursor = self.cursors[0]
        rows = PostgresAuthzAnalyzer._get_rows(pg_cursor, command)
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

    def _get_roles_grants(self) -> Dict[RoleName, Set[ResourceGrant]]:
        command = (COMMANDS_DIR / "roles_grants.sql").read_text()
        results: Dict[RoleName, Set[ResourceGrant]] = {}
        for pg_cursor in self.cursors:
            rows = PostgresAuthzAnalyzer._get_rows(pg_cursor, command)
            for row in rows:
                _grantor = row[0]
                role = row[1]
                table_name = row[2]
                level = PERMISSION_LEVEL_MAP[row[3]]

                role_grants = results.setdefault(role, set())
                role_grants.add(ResourceGrant(table_name, level))

        return results

    def _add_super_user(self, role_to_grants: Dict[RoleName, Set[ResourceGrant]]):
        self.logger.info("Fetching all tables")
        command = (COMMANDS_DIR / "all_tables.sql").read_text()
        all_tables: Set[ResourceGrant] = set()
        for pg_cursor in self.cursors:
            rows = PostgresAuthzAnalyzer._get_rows(pg_cursor, command)
            for table_name in rows:
                all_tables.add(ResourceGrant(table_name[0], PermissionLevel.FULL))
        role_to_grants["super_user"] = all_tables

    @staticmethod
    def _get_rows(postgres_cursor: cursor, command: str):
        postgres_cursor.execute(command)
        return postgres_cursor.fetchall()
