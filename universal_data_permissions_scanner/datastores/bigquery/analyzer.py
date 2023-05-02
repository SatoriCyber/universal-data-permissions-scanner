"""This analyzer uses data from BigQuery and GCP IAM to list all possible permissions to BigQuery tables/views.

Bigquery authorization is based on GCP IAM.
With IAM, you manage access control by defining who (identity) has what access (role) for which resource.
In IAM, permission to access a resource isn't granted directly to the end user,
Instead, permissions are grouped into roles, and roles are granted to authenticated principals.
This model for access management has three main parts:

Principal:
A principal can be a Google Account (for end users).
A service account (for applications and compute workloads).
A Google group.
A Google Workspace account or Cloud Identity domain that can access a resource.
Each principal has its own identifier, which is typically an email address.

Role:
A role is a collection of permissions.
Permissions determine what operations are allowed on a resource.
When you grant a role to a principal, you grant all the permissions that the role contains.

Policy:
The allow policy is a collection of role bindings that bind one or more principals to individual roles.
When you want to define who (principal) has what type of access (role) on a resource,
you create an allow policy and attach it to the resource.

You can grant access to a project.
Most services support IAM permission with finer granularity,
like access to specific bucket at the storage and etc'.

There are several kinds of roles in IAM:
Basic roles: Roles historically available in the Google Cloud console. These roles are Owner, Editor, and Viewer.
Predefined roles
Custom roles

Resource hierarchy

The organization is the root node in the hierarchy.
Folders are children of the organization.
Projects are children of the organization, or of a folder.
Resources for each service are descendants of projects.

Resources inherit the allow policies of all of their parent resources

The canonical structure of a the authorization graph is as follows:
Table - may have permissions defined directly on it and inherits the permissions from the dataset.
Dataset - may have permissions defined directly on it and potentially inherits some permissions from the project.
Project - may have permissions defined directly on it and inherits the permissions from the folder it's contained in.
Folder -  may have permissions defined directly on it and inherits the permissions from its parent folder(s) or organization
Organization - may have permissions defined directly on it
Permissions are defined using roles, see the mapping of role to permissions in the policy_tree module.
"""

import json
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Any, List, Optional, Union

from google.api_core.page_iterator import Iterator  # type: ignore
from google.cloud.bigquery.table import TableListItem  # type: ignore
from google.oauth2.service_account import Credentials  # type: ignore

from universal_data_permissions_scanner.datastores.bigquery.policy_tree import (
    GRANTED_BY_TO_PATHZ_ELEMENT,
    READ_PERMISSIONS,
    WRITE_PERMISSIONS,
    CustomPermission,
    DatasetPolicyNode,
    Member,
    PolicyNode,
    TableIamPolicyNode,
)
from universal_data_permissions_scanner.datastores.bigquery.service import BigQueryService
from universal_data_permissions_scanner.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzNote,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    PermissionLevel,
)
from universal_data_permissions_scanner.utils.logger import get_logger
from universal_data_permissions_scanner.writers import BaseWriter
from universal_data_permissions_scanner.writers.base_writers import DEFAULT_OUTPUT_FILE, OutputFormat
from universal_data_permissions_scanner.writers.get_writers import get_writer


@dataclass
class BigQueryAuthzAnalyzer:
    """BigQuery authorization analyzer."""

    logger: Logger
    service: BigQueryService
    writer: BaseWriter

    @classmethod
    def connect(
        cls,
        project_id: str,
        logger: Optional[Logger] = None,
        output_format: OutputFormat = OutputFormat.CSV,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
        credentials_str: Optional[str] = None,
        **kwargs: Any,
    ):
        """Connect to BigQuery and return an instance of the analyzer.

        Args:
            project_id (str): GCP project id to analyze.
            logger (Optional[Logger], optional): Python logger. Defaults to None.
            output_format (OutputFormat, optional): file format to export. Defaults to OutputFormat.CSV.
            output_path (Union[Path, str], optional): Path to write the file. Defaults to ./authz-analyzer-export.
            credentials_str (Optional[str], optional): ServiceAccount to connect to BigQuery. Defaults to None.
        """
        writer = get_writer(filename=output_path, output_format=output_format)
        if logger is None:
            logger = get_logger(False)
        if credentials_str is not None:
            credentials = Credentials.from_service_account_info(json.loads(credentials_str))  # type: ignore
            big_query_service = BigQueryService.load(project_id, credentials=credentials, **kwargs)
        else:
            big_query_service = BigQueryService.load(project_id, **kwargs)
        return cls(logger, big_query_service, writer=writer)

    def run(self) -> None:
        """Read all tables in all datasets and calculate authz paths"""
        self.logger.info("Starting BigQuery authorization analysis for project %s", self.service.project_id)
        project_node = self.service.lookup_project(self._resolve_custom_role_to_permissions)
        for dataset_id in self.service.list_datasets():
            self.logger.info("Scanning dataset %s", dataset_id)
            dataset = self.service.get_dataset(dataset_id)
            dataset_node = DatasetPolicyNode(dataset, self._resolve_custom_role_to_permissions)
            dataset_node.set_parent(project_node)
            tables: Iterator = self.service.list_tables(dataset_id)
            table: TableListItem
            for table in tables:
                fq_table_id = f"{table.project}.{table.dataset_id}.{table.table_id}"  # type: ignore
                table_iam = self.service.get_table_policy(table.reference)
                name: str = table.table_id  # type: ignore
                table_node = TableIamPolicyNode(
                    table_id=fq_table_id,
                    name=name,
                    policy=table_iam,
                    resolve_permission_callback=self._resolve_custom_role_to_permissions,
                )
                table_node.set_parent(dataset_node)
                self._calc(Asset([fq_table_id], type=AssetType.TABLE), table_node, [])
        self.writer.close()

    def _calc(
        self,
        fq_table_id: Asset,
        node: PolicyNode,
        path: List[AuthzPathElement],
        permissions: Optional[List[PermissionLevel]] = None,
    ):
        """
        Calculates permissions on the policy node and recursively search for more permissions
        on the nodes it references or its parent node.
        """

        if permissions is None:
            permissions = [PermissionLevel.READ, PermissionLevel.WRITE, PermissionLevel.FULL]
        self.logger.debug(
            "calc for %s %s %s permissions = %s path = %s}",
            fq_table_id,
            node.type,
            node.name,
            permissions,
            list(map(lambda x: x.type, path)),
        )
        # Start by listing all immediate permissions defined on this node
        for permission in permissions:
            for member in node.get_members(permission):
                self._report_permission(fq_table_id, node, member, permission, path)  # type: ignore

        # Then go to each reference and get the permissions from it
        for permission in permissions:
            for member in node.get_references(permission):
                ref_node = self.service.lookup_ref(member.name, self._resolve_custom_role_to_permissions)
                if ref_node is None:
                    self.logger.error("Unable to find ref_node for member %s", member)
                    continue
                note = f"{node.type} references {ref_node.type.lower()} {ref_node.name} with permission {permission}"
                self._add_to_path(path, node, note, member.db_permissions)
                self._calc(fq_table_id, ref_node, path, permissions=[permission])
                path.pop()

        # Finally, go to the parent and get the inherited permissions
        if node.parent is not None:
            self._goto_parent(fq_table_id, node, path, permissions)

    def _goto_parent(
        self, fq_table_id: Asset, node: PolicyNode, path: List[AuthzPathElement], permissions: List[PermissionLevel]
    ):
        note = f"{node.type.lower()} {node.name} is included in {node.parent.type.lower()} {node.parent.name}"  # type: ignore
        self._add_to_path(path, node, note, [])
        self._calc(fq_table_id, node.parent, path, permissions)  # type: ignore
        path.pop()

    def _add_to_path(
        self, path: List[AuthzPathElement], node: PolicyNode, note: str, db_permissions: Optional[List[str]]
    ):
        if db_permissions is None:
            db_permissions = []
        self.logger.debug("Adding %s %s to path", node.type, node.name)
        authz_type = GRANTED_BY_TO_PATHZ_ELEMENT[node.type]
        path.append(
            AuthzPathElement(
                node.id, node.name, authz_type, notes=[AuthzNote.to_generic_note(note)], db_permissions=db_permissions
            )
        )

    def _add_role_to_path(self, path: List[AuthzPathElement], member: Member):
        self.logger.debug("Adding role %s to path", member.role)
        path.append(
            AuthzPathElement(
                member.role,
                member.role,
                AuthzPathElementType.ROLE,
                [AuthzNote.to_generic_note(f"Role {member.role} is granted to {member.name}")],
                db_permissions=member.db_permissions,
            )
        )

    def _report_permission(
        self,
        fq_table_id: Asset,
        node: PolicyNode,
        member: Member,
        permission: PermissionLevel,
        path: List[AuthzPathElement],
    ):
        note = f"{member.name} has role {member.role}"
        self._add_to_path(path, node, note, [])
        self._add_role_to_path(path, member)
        reversed_path = list(reversed(path))

        identity = Identity(id=f"{member.original_identity_type}:{member.name}", type=member.type, name=member.name)
        authz = AuthzEntry(fq_table_id, path=reversed_path, identity=identity, permission=permission)
        self.writer.write_entry(authz)
        path.pop()
        path.pop()

    def _resolve_custom_role_to_permissions(self, role: str) -> Optional[CustomPermission]:
        """
        Resolve role to the highest permission level it has, or None if it has no permissions to bigquery
        """
        row_permissions = self.service.get_permissions_by_role(role)
        db_permissions: List[str] = []
        highest_permission: Optional[PermissionLevel] = None
        for row_permission in row_permissions:
            if row_permission in WRITE_PERMISSIONS:
                highest_permission = PermissionLevel.WRITE
                db_permissions.append(row_permission)
            if row_permission in READ_PERMISSIONS:
                highest_permission = PermissionLevel.READ
                db_permissions.append(row_permission)
        if highest_permission is None:
            return None
        return CustomPermission(db_permissions, highest_permission)
