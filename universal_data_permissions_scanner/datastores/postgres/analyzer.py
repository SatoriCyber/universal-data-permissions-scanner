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
from typing import Any, Dict, Generator, List, Optional, Set, Tuple, Union

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT, connection, cursor

from universal_data_permissions_scanner.datastores.postgres import exporter
from universal_data_permissions_scanner.datastores.postgres.database_query_results import DataBaseAcl
from universal_data_permissions_scanner.datastores.postgres.database_query_results import RoleGrant as DataBaseRoleGrant
from universal_data_permissions_scanner.datastores.postgres.deployment import Deployment
from universal_data_permissions_scanner.datastores.postgres.model import (
    PERMISSION_LEVEL_MAP,
    RESOURCE_TYPE_MAP,
    AuthorizationModel,
    DBRole,
    ResourceGrant,
    RoleName,
)
from universal_data_permissions_scanner.models.model import AssetType, PermissionLevel
from universal_data_permissions_scanner.utils.logger import get_logger
from universal_data_permissions_scanner.writers import BaseWriter, OutputFormat, get_writer
from universal_data_permissions_scanner.writers.base_writers import DEFAULT_OUTPUT_FILE

from universal_data_permissions_scanner.errors.failed_connection_errors import ConnectionFailure

COMMANDS_DIR = Path(__file__).parent / "commands"

DbName = str


@dataclass
class PostgresAuthzAnalyzer:
    """Analyze authorization for Postgres."""

    cursors: Dict[DbName, cursor]
    writer: BaseWriter
    logger: Logger
    deployment: Deployment

    @classmethod
    def connect(  # pylint: disable=too-many-locals
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
            output_format (OutputFormat, optional): Output format. Defaults to OutputFormat.CSV.
            credentials_str (Optional[str], optional): ServiceAccount to connect to BigQuery. Defaults to None.
        """
        if logger is None:
            logger = get_logger(False)

        writer = get_writer(filename=output_path, output_format=output_format)

        try:
            connector: psycopg2.connection = psycopg2.connect(  # pylint: disable=E1101:no-member #type: ignore
                user=username, password=password, host=host, dbname=dbname, **connection_kwargs
            )
        except Exception as err:
            raise ConnectionFailure from err
        connector.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

        # We generate cursor one per database in order to fetch the table grants and the information schema
        postgres_cursors: Dict[DbName, cursor] = {}
        deployment = Deployment.other()
        for database in PostgresAuthzAnalyzer._get_all_databases(connector):
            if database == "rdsadmin":
                deployment = Deployment.aws_rds()
                logger.debug("Skipping rdsadmin database, internal use by AWS")
                continue
            if database == "cloudsqladmin":
                deployment = Deployment.gcp()
                logger.debug("Skipping cloudsqladmin database, internal use by GCP")
                continue
            db_connector: psycopg2.connection = psycopg2.connect(  # pylint: disable=E1101:no-member #type: ignore
                user=username, password=password, host=host, dbname=database, **connection_kwargs
            )
            postgres_cursors[database] = db_connector.cursor()
        return cls(logger=logger, cursors=postgres_cursors, writer=writer, deployment=deployment)

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
    def _get_all_databases(
        connector: connection,
    ):
        postgres_cursor = connector.cursor()
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
        pg_cursor = next(iter(self.cursors.values()))
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
        results: Dict[RoleName, Set[ResourceGrant]] = {}
        for db_name, pg_cursor in self.cursors.items():
            rows = PostgresAuthzAnalyzer._get_roles_grants_from_db(pg_cursor)
            for role, resource_grant in self._yield_resource_grant_from_role_grants(
                db_name=db_name, database_roles=rows
            ):
                role_grants = results.setdefault(role, set())
                role_grants.add(resource_grant)

        return results

    def _yield_resource_grant_from_role_grants(
        self, db_name: str, database_roles: List[DataBaseRoleGrant]
    ) -> Generator[Tuple[RoleName, ResourceGrant], None, None]:
        for database_role in database_roles:
            resource_name = [db_name, database_role.schema_name, database_role.resource_name]
            try:
                resource_type = RESOURCE_TYPE_MAP[database_role.resource_type]
            except KeyError:
                self.logger.debug("Skipping resource type %s", database_role.resource_type)
                continue

            yield database_role.owner, ResourceGrant(
                name=resource_name,
                permission_level=PermissionLevel.FULL,
                db_permissions=["OWNERSHIP"],
                type=resource_type,
            )
            if database_role.acl is not None:
                acl_entry = DataBaseAcl.serialize_from_str(self.logger, database_role.acl)
                for entry in acl_entry.entries:
                    try:
                        permission_level = PERMISSION_LEVEL_MAP.get(
                            entry.max_permission().name, PermissionLevel.UNKNOWN
                        )
                    except ValueError:
                        self.logger.warning("no relevant permissions found for role")
                        continue
                    yield entry.grantee, ResourceGrant(
                        name=resource_name,
                        permission_level=permission_level,
                        db_permissions=[db_permission.name for db_permission in entry.permissions],
                        type=resource_type,
                    )

    @staticmethod
    def _get_high_permission_level() -> Set[RoleName]:
        return {"super_user", "rds_superuser"}

    def _add_super_user(self, role_to_grants: Dict[RoleName, Set[ResourceGrant]]):
        self.logger.info("Fetching all tables")
        command = (COMMANDS_DIR / "all_tables.sql").read_text()
        all_tables: Set[ResourceGrant] = set()
        for pg_cursor in self.cursors.values():
            rows = PostgresAuthzAnalyzer._get_rows(pg_cursor, command)

            for row in rows:
                db: str = row[0]  # type: ignore #pylint: disable=invalid-name
                schema = row[1]  # type: ignore
                table = row[2]  # type: ignore
                all_tables.add(
                    ResourceGrant(
                        [db, schema, table], PermissionLevel.FULL, db_permissions=["super_user"], type=AssetType.TABLE
                    )
                )
        managed_super_user = self.deployment.get_cloud_super_user()
        if managed_super_user is not None:
            role_to_grants[managed_super_user] = all_tables
        role_to_grants["super_user"] = all_tables

    @staticmethod
    def _get_rows(postgres_cursor: cursor, command: str):
        postgres_cursor.execute(command)
        return postgres_cursor.fetchall()

    @staticmethod
    def _get_roles_grants_from_db(postgres_cursor: cursor):
        command = (COMMANDS_DIR / "roles_grants.sql").read_text()
        return [
            DataBaseRoleGrant(row[0], row[1], row[2], row[3], row[4])
            for row in PostgresAuthzAnalyzer._get_rows(postgres_cursor, command)
        ]
