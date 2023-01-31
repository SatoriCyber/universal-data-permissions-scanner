"""Analyze authorization for Redshift.

https://discourse.getdbt.com/t/the-difference-between-users-groups-and-roles-on-postgres-redshift-and-snowflake/429
RedShift based on postgres8
Only users can be members of groups, i.e. a group cannot be a member of other groups
Only users can own relations
Both users and groups can have privileges granted to them

The database will not let you set up circular membership loops.
"""

from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import redshift_connector  # type: ignore

from authz_analyzer.datastores.aws.analyzer.redshift import exporter
from authz_analyzer.datastores.aws.analyzer.redshift.model import (
    PERMISSION_LEVEL_MAP,
    AuthorizationModel,
    DBIdentity,
    IdentityId,
    IdentityType,
    ResourcePermission,
)
from authz_analyzer.datastores.aws.analyzer.redshift.service import RedshiftService
from authz_analyzer.models import PermissionLevel
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE

COMMANDS_DIR = Path(__file__).parent / "commands"


@dataclass
class RedshiftAuthzAnalyzer:
    """Analyze authorization for Redshift."""

    cursors: List[redshift_connector.Cursor]
    writer: BaseWriter
    logger: Logger
    service: RedshiftService = RedshiftService()

    @classmethod
    def connect(
        cls,
        username: str,
        password: str,
        host: str,
        port: int,
        dbname: str,
        logger: Optional[Logger] = None,
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
        **connection_kwargs: Any,
    ):
        """Connect to Redshift and return an analyzer.

        Args:
            username (str): Redshift username
            password (str): Redshift password
            host (str): Redshift host, can be a hostname or an IP address
            dbname (str): Redshift database name
            logger (Optional[Logger], optional): Python logger. Defaults to None.
            output_path (Union[Path, str], optional): Path to write the file. Defaults to ./authz-analyzer-export.
            output_format (OutputFormat, optional): Output format. Defaults to OutputFormat.CSV.
        """
        if logger is None:
            logger = get_logger(False)

        writer = get_writer(filename=output_path, output_format=output_format)
        connector: redshift_connector.Connection = redshift_connector.connect(
            user=username, password=password, host=host, port=port, database=dbname
        )
        redshift_cursor = connector.cursor()

        # We generate cursor one per database in order to fetch the table grants and the information schema
        redshift_cursors: List[redshift_connector.Cursor] = []
        for database in RedshiftAuthzAnalyzer._get_all_databases(redshift_cursor):
            if database == "rdsadmin":
                logger.debug("Skipping rdsadmin database, internal use by AWS")
                continue
            db_connector: redshift_connector.Connection = redshift_connector.connect(
                user=username, password=password, host=host, database=database
            )
            redshift_cursors.append(db_connector.cursor())
        return cls(logger=logger, cursors=redshift_cursors, writer=writer)

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
    def _get_all_databases(redshift_cursor: redshift_connector.Cursor):
        return {database[0] for database in RedshiftService.get_rows(redshift_cursor, Path("all_databases.sql"))}

    def _get_authorization_model(self):
        self.logger.info("Fetching identities with relations")
        identity_to_identities = self._get_identity_identities_mapping()

        self.logger.info("Fetching identities to table privileges")
        identity_to_resource_privilege = self._get_identities_privileges()

        self.logger.info("Fetching all tables for super users")
        self._add_super_user_privileges(identity_to_resource_privilege)

        return AuthorizationModel(
            identity_to_identities=identity_to_identities,
            identity_to_resource_privilege=identity_to_resource_privilege,
        )

    def _get_identity_identities_mapping(self) -> Dict[DBIdentity, Set[DBIdentity]]:
        results: Dict[DBIdentity, Set[DBIdentity]] = {}

        # For identities, it is shared per cluster, there is no need to pull per DB
        pg_cursor = self.cursors[0]
        rows = self.service.get_rows(pg_cursor, Path("identities.sql"))
        for row in rows:
            identity_id: IdentityId = row[0]
            identity_name: str = row[1]
            identity_type: IdentityType = IdentityType(row[2])
            granted_identity_id: IdentityId = row[3]
            granted_identity_name: str = row[4]
            try:
                granted_identity_type: IdentityType = IdentityType(row[5])
            except ValueError:
                granted_identity_type = IdentityType.UNKNOWN
            is_admin: bool = row[6]

            identity = DBIdentity.new(id_=identity_id, name=identity_name, identity_type=identity_type, relations=set())

            identity_grants = results.setdefault(identity, set())
            if granted_identity_id is not None:
                granted_identity = DBIdentity.new(
                    id_=granted_identity_id,
                    name=granted_identity_name,
                    identity_type=granted_identity_type,
                    relations=set(),
                )
                identity_grants.add(granted_identity)
            if identity.type is IdentityType.USER:
                identity_grants.add(
                    DBIdentity.new(id_=0, name="public", identity_type=IdentityType.GROUP, relations=set())
                )
            if is_admin:
                identity_grants.add(
                    DBIdentity.new(id_=-1, name="super_user", identity_type=IdentityType.ROLE, relations=set())
                )

        return results

    def _get_identities_privileges(self) -> Dict[IdentityId, Dict[str, Set[ResourcePermission]]]:
        results: Dict[IdentityId, Dict[str, Set[ResourcePermission]]] = {}
        for pg_cursor in self.cursors:
            db_name = pg_cursor.connection._database  # type: ignore
            rows = self.service.get_rows(pg_cursor, Path("identities_privileges.sql"))
            for row in rows:
                _grantor = row[0]
                identity = row[1]
                schema_name = row[2]
                table_name = row[3]
                db_permission = row[4]
                level = PERMISSION_LEVEL_MAP.get(db_permission, PermissionLevel.UNKNOWN)

                identity_grants_to_table = results.setdefault(identity, {})
                asset_path = [db_name, schema_name, table_name]
                full_table_name = ".".join(asset_path)
                resource_permissions = identity_grants_to_table.setdefault(full_table_name, set())
                updated: bool = False
                # create resource permission level
                for resource_permission in resource_permissions:
                    if resource_permission.permission_level == level:
                        updated = True
                        resource_permission.db_permissions.append(db_permission)
                # otherwise, update existing permission level
                if not updated:
                    resource_permissions.add(ResourcePermission(asset_path, level, [db_permission]))

        return results

    def _add_super_user_privileges(
        self, identity_to_resource_privilege: Dict[IdentityId, Dict[str, Set[ResourcePermission]]]
    ):
        """Add to super user role full permissions to all tables in all databases."""
        super_user_permissions: Dict[str, Set[ResourcePermission]] = {}
        for pg_cursor in self.cursors:
            for row in self.service.get_rows(pg_cursor, Path("all_tables.sql")):
                db: str = row[0]
                schema: str = row[1]
                table: str = row[2]
                _resource_type: str = row[0]
                full_table_name = ".".join([db, schema, table])

                table_permissions = super_user_permissions.setdefault(full_table_name, set())
                table_permissions.add(
                    ResourcePermission(
                        name=[db, schema, table], permission_level=PermissionLevel.FULL, db_permissions=["ALL"]
                    )
                )
        identity_to_resource_privilege[-1] = super_user_permissions