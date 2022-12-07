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
from typing import Any, List, Optional, Tuple, Union

import networkx as nx
import snowflake.connector
from snowflake.connector.cursor import SnowflakeCursor

from authz_analyzer.datastores.base import BaseAuthzAnalyzer
from authz_analyzer.datastores.snowflake.model import (
    permission_level_from_str,
)
from authz_analyzer.exporters import graph_exporter
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter, OutputFormat, get_writer
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE

from authz_analyzer.models.graph_model import Node, init_graph, ResourceNode

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
        (authorization_graph, start_node, end_node) = init_graph()
        self.logger.info("Starting to  query")
        self._build_authorization_graph(authorization_graph, start_node, end_node)
        self.logger.info("Starting to Analyze")
        graph_exporter.export(graph=authorization_graph, start_node=start_node, end_node=end_node, writer=self.writer)
        self.logger.info("Finished analyzing")
        self.writer.close()

    def _add_users_to_graph(self, graph: nx.DiGraph, start_node: Node):
        rows: List[Tuple[str, str]] = self._get_rows(file_name_command=Path("user_grants.sql"))
        for row in rows:
            user_node = Node.create_granted_to(name=row[0])
            role_node = Node.create_granter(name=row[1])

            graph.add_edge(start_node, user_node)
            graph.add_edge(user_node, role_node)

    def _add_roles_and_resources(self, graph: nx.DiGraph, end_node: Node):
        rows: List[Tuple[str, str, str, str, str]] = self._get_rows(
            file_name_command=Path("grants_roles.sql")
        )
        for row in rows:
            name: str = row[0]
            role: str = row[1]
            permission_level = row[2]
            table_name: str = row[3]
            granted_on: str = row[4]

            if permission_level == "USAGE" and granted_on == "ROLE":
                graph.add_edge(Node.create_granter(name=role), Node.create_granter(name=name))
            
            elif table_name is not None and granted_on in ("TABLE", "VIEW", "MATERIALIZED VIEW"):
                resource_node = ResourceNode(name=table_name, permission_level=permission_level_from_str(permission_level))
                graph.add_edge(Node.create_granter(name=role), resource_node)
                graph.add_edge(resource_node, end_node)

    def _build_authorization_graph(self, graph: nx.DiGraph, start_node: Node, end_node: Node):
        self.logger.info("Fetching users to roles grants")
        self._add_users_to_graph(graph, start_node)
        self._add_roles_and_resources(graph, end_node)


    def _get_rows(self, file_name_command: Path) -> List[Tuple[Any, ...]]:
        command = (COMMANDS_DIR / file_name_command).read_text(encoding="utf-8")
        self.cursor.execute(command)
        return self.cursor.fetchall()  # type: ignore
