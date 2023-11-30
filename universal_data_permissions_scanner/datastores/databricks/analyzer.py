from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Any, Optional, Union

from databricks_cli.sdk.api_client import ApiClient  # type: ignore
from databricks_cli.unity_catalog.uc_service import UnityCatalogService  # type: ignore

from universal_data_permissions_scanner.datastores.databricks.identities import Identities
from universal_data_permissions_scanner.datastores.databricks.policy_tree import CatalogNode, ResourceNode, SchemaNode
from universal_data_permissions_scanner.datastores.databricks.service.model import (
    CatalogList,
    PrivilegeAssignments,
    Schema,
    Table,
)
from universal_data_permissions_scanner.datastores.databricks.service.scim import ScimService
from universal_data_permissions_scanner.utils.logger import get_logger
from universal_data_permissions_scanner.writers.base_writers import DEFAULT_OUTPUT_FILE, BaseWriter, OutputFormat
from universal_data_permissions_scanner.writers.get_writers import get_writer

from universal_data_permissions_scanner.datastores.databricks.service.authentication import (
    Authentication,
)


from universal_data_permissions_scanner.datastores.databricks.service.authentication.basic import BasicAuthentication

from universal_data_permissions_scanner.datastores.databricks.service.authentication.oauth import (
    OauthProvider,
    get_authentication_token,
)


@dataclass
class DatabricksAuthzAnalyzer:
    writer: BaseWriter
    logger: Logger
    unity_catalog_service: UnityCatalogService
    scim_service: ScimService
    metastore_id: Optional[str] = None

    @classmethod
    def connect(
        cls,
        host: str,
        authentication: Authentication,
        account_id: str,
        metastore_id: Optional[str] = None,
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
        logger: Optional[Logger] = None,
        **kwargs: Any,
    ):
        """Analyzer authorization for Databricks

        Args:
            host (str): instance url, e.g. https://dbc-a1b2345c-d6e7.cloud.databricks.com
            authentication: Authentication method, either basic or oauth
            output_format (OutputFormat, optional): Output format. Defaults to OutputFormat.CSV.
            output_path (Union[Path, str], optional): Output path. Defaults to Path.cwd()/DEFAULT_OUTPUT_FILE.
            logger (Optional[Logger], optional): Logger. Defaults to None.

        Returns:
            cls: instance
        """
        writer = get_writer(filename=output_path, output_format=output_format)
        if logger is None:
            logger = get_logger(False)
        logger.debug("Connecting to Databricks instance at %s", host)
        if isinstance(authentication.authentication, BasicAuthentication):
            api_client = ApiClient(
                host=host,
                user=authentication.authentication.username,
                password=authentication.authentication.password,
                **kwargs,
            )
        elif isinstance(authentication.authentication, OauthProvider):  # type: ignore
            token = get_authentication_token(authentication.authentication)
            api_client = ApiClient(host=host, token=token, **kwargs)
        else:
            raise ValueError("Unknown authentication method")
        unity_catalog_service = UnityCatalogService(api_client)
        scim_service = ScimService.load(authentication, account_id, host)
        return cls(
            writer=writer,
            logger=logger,
            unity_catalog_service=unity_catalog_service,
            scim_service=scim_service,
            metastore_id=metastore_id,
        )

    def run(self):
        """Run the analyzer"""
        self.logger.debug("Starting to analyzer Databricks, fetching users")
        users = self.scim_service.list_users()["Resources"]
        self.logger.debug("fetching groups")
        groups = self.scim_service.list_groups()["Resources"]
        self.logger.debug("fetching service principals")
        service_principal = self.scim_service.list_service_principals()["Resources"]

        identities = Identities.build_from_databricks_response(self.logger, users, groups, service_principal)
        self.logger.info("Starting to analyze catalogs")
        catalog: CatalogList
        for catalog in self.unity_catalog_service.list_catalogs()["catalogs"]:  # type: ignore
            if self.metastore_id is not None and catalog["metastore_id"] != self.metastore_id:
                self.logger.error("Catalog %s does not match metastore_id %s", catalog["name"], self.metastore_id)
                continue
            self.logger.info("Analyzing catalog: %s", catalog["name"])
            for entry in self._iter_permissions_catalog(catalog, identities):
                self.logger.debug("Writing entry: %s", entry)
                self.writer.write_entry(entry)

    def _iter_permissions_catalog(self, catalog: CatalogList, identities: Identities):
        catalog_node = CatalogNode(self.logger, catalog["name"], catalog["owner"])
        self.logger.debug("Starting to analyze schemas")
        schema: Schema
        for schema in self.unity_catalog_service.list_schemas(catalog["name"])["schemas"]:  # type: ignore
            self.logger.info("Analyzing schema: %s", schema["name"])
            schema_node = SchemaNode(self.logger, schema["name"], catalog_node, schema["owner"])
            yield from self._iter_tables(schema_node, identities)

    def _iter_tables(self, schema_node: SchemaNode, identities: Identities):
        table: Table
        for table in self.unity_catalog_service.list_tables(catalog_name=schema_node.parent.name, schema_name=schema_node.name).get("tables", []):  # type: ignore
            self.logger.debug("Analyzing table: %s", table["full_name"])
            table_node = self._build_table_node(table, schema_node)
            yield from table_node.iter_permissions(identities.resolve_identities)

    def _build_table_node(self, table: Table, parent: SchemaNode):
        resource_node = ResourceNode(
            self.logger, table["name"], parent, resource_type=table["table_type"], ownership=table["owner"]
        )
        privilege_assignments: PrivilegeAssignments
        for privilege_assignments in self.unity_catalog_service.get_effective_permissions("TABLE", table["full_name"]).get("privilege_assignments", []):  # type: ignore
            resource_node.add_privilege_assignments(privilege_assignments)
        return resource_node
