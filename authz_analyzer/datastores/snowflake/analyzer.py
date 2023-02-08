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

from authz_analyzer.datastores.snowflake import exporter
from authz_analyzer.datastores.snowflake.model import (
    PERMISSION_LEVEL_MAP,
    AuthorizationModel,
    DataShare,
    DataShareKind,
    DataSharePrivilege,
    DBRole,
    GrantedOn,
    PermissionType,
    ResourceGrant,
    User,
)
from authz_analyzer.datastores.snowflake.service import SnowflakeService
from authz_analyzer.models.model import PermissionLevel
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE

COMMANDS_DIR = Path(__file__).parent / "commands"


@dataclass
class SnowflakeAuthzAnalyzer:
    """Analyze authorization for Snowflake."""

    service: SnowflakeService
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
        service = SnowflakeService(cursor)
        return cls(service=service, logger=logger, writer=writer)

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

    def _get_users_to_role_mapping(self) -> Dict[User, Set[DBRole]]:
        rows: List[Tuple[str, str, Optional[str]]] = self.service.get_rows(file_name_command=Path("user_grants.sql"))  # type: ignore

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
    def _is_the_same_resource(
        table_name: List[str], permission_level: PermissionLevel, granted_on: GrantedOn, resource: ResourceGrant
    ) -> bool:
        return (
            resource.name == table_name
            and resource.permission_level == permission_level
            and resource.granted_on == granted_on
        )

    @staticmethod
    def create_resource_grant(
        table_name: List[str],
        database_level: PermissionType,
        granted_on: GrantedOn,
    ):
        level = PERMISSION_LEVEL_MAP[database_level]
        return ResourceGrant(table_name, level, [database_level], granted_on=granted_on)

    def _get_role_to_roles_and_role_to_resources(self) -> Tuple[Dict[str, Set[DBRole]], Dict[str, Set[ResourceGrant]]]:
        rows = self.service.get_rows(file_name_command=Path("grants_roles.sql"))
        role_to_roles: Dict[str, Set[DBRole]] = {}
        role_to_resources: Dict[str, Set[ResourceGrant]] = {}

        current_resource_grant: Optional[ResourceGrant] = None
        current_role: Optional[str] = None
        for row in rows:
            role: str = row[0]
            try:
                privilege = PermissionType(row[1])
            except ValueError:
                self.logger.debug("Privilege doesn't grant permission to data, skipping privilege %s", row[1])
                continue
            db: str = row[2]
            schema: str = row[3]
            resource_name: str = row[4]
            granted_on = GrantedOn.from_str(row[5])

            if privilege is PermissionType.USAGE and granted_on == GrantedOn.ROLE:
                SnowflakeAuthzAnalyzer._add_role_to_roles(role, resource_name, role_to_roles)

            elif resource_name is not None and granted_on in (
                GrantedOn.TABLE,
                GrantedOn.VIEW,
                GrantedOn.MATERIALIZED_VIEW,
            ):
                permission_level = PERMISSION_LEVEL_MAP[privilege]
                table_name = [db, schema, resource_name]
                if current_resource_grant is None:
                    current_role = role
                    current_resource_grant = SnowflakeAuthzAnalyzer.create_resource_grant(
                        table_name, privilege, granted_on
                    )
                elif (
                    current_resource_grant is not None
                    and SnowflakeAuthzAnalyzer._is_the_same_resource(
                        table_name, permission_level, granted_on, current_resource_grant
                    )
                    and current_role == role
                ):
                    current_resource_grant.db_permissions.append(privilege)
                else:
                    role_to_resources.setdefault(role, set()).add(current_resource_grant)
                    current_resource_grant = SnowflakeAuthzAnalyzer.create_resource_grant(
                        table_name, privilege, granted_on
                    )
                    current_role = role
        if current_resource_grant is not None and current_role is not None:
            role_to_resources.setdefault(current_role, set()).add(current_resource_grant)
        return role_to_roles, role_to_resources

    def _get_authorization_model(self):
        self.logger.info("Fetching users to roles grants")
        users_to_roles = self._get_users_to_role_mapping()
        role_to_roles, roles_to_grants = self._get_role_to_roles_and_role_to_resources()
        shares = self._get_data_shares()

        return AuthorizationModel(
            users_to_roles=users_to_roles, role_to_roles=role_to_roles, roles_to_grants=roles_to_grants, shares=shares
        )

    def _get_data_shares(self) -> Set[DataShare]:
        rows = self.service.get_rows(file_name_command=Path("shares.sql"))
        results: Set[DataShare] = set()
        for row in rows:
            kind = DataShareKind(row[1])
            share_id: List[str] = row[2].split(".")
            share_name = share_id[-1]
            share_to_accounts: str = row[4]
            splitted_share_to_accounts = share_to_accounts.split(",") if share_to_accounts is not None else []
            if kind is DataShareKind.OUTBOUND and share_to_accounts != "":
                self.logger.debug("Found an outbound data share %s", share_name)
                privileges = self._get_privileges_data_share(share_name=share_name)
                share = DataShare(
                    name=share_name, share_to_accounts=splitted_share_to_accounts, privileges=privileges, id=share_id
                )
                results.add(share)

        return results

    def _get_privileges_data_share(self, share_name: str) -> Set[DataSharePrivilege]:
        rows = self.service.get_rows(file_name_command=Path("grants_to_share.sql"), params=share_name)
        privileges: Set[DataSharePrivilege] = set()
        for row in rows:
            try:
                database_permission = PermissionType(row[1])
            except ValueError:
                self.logger.debug("Privilege doesn't grant permission to data, skipping privilege %s", row[1])
                continue
            try:
                permission_level = PERMISSION_LEVEL_MAP[database_permission]
            except KeyError:
                self.logger.debug("Privilege doesn't grant permission to data, skipping privilege %s", row[1])
                continue
            granted_on = row[2]
            resource_name: List[str] = row[3].split(".")
            privileges.add(
                DataSharePrivilege(
                    permission_level=permission_level,
                    granted_on=granted_on,
                    database_permission=database_permission,
                    resource_name=resource_name,
                )
            )
        return privileges
