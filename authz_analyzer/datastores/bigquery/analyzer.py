"""This analyzer uses data from BigQuery and GCP IAM to list all possible permissions to BigQuery tables/views.

Bigquery authorization is based on GCP IAM.
With IAM, you manage access control by defining who (identity) has what access (role) for which resource.
In IAM, permission to access a resource isn't granted directly to the end user.
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

All authenticated users
The value allAuthenticatedUsers is a special identifier that represents 
all service accounts and all users on the internet who have authenticated with a Google Account. 
This identifier includes accounts that aren't connected to a Google Workspace account or Cloud Identity domain, 
such as personal Gmail accounts. 
Users who aren't authenticated, such as anonymous visitors, aren't included.
This principal type doesn't include identities that come from external identity providers (IdPs). 
If you use workforce identity federation or workload identity federation, don't use allAuthenticatedUsers. Instead, use one of the following:

To include users from all IdPs, use allUsers.
To include users from specific external IdPs, 
use the identifier for all identities in a workforce identity pool or all identities in a workload identity pool.

All users
The value allUsers is a special identifier that represents anyone who is on the internet, 
including authenticated and unauthenticated users.

You can grant access to a project.
Most services support IAM permission with finer granularity, like access to specific bucket at the storage and etc'.

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

from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import List, Optional, TypedDict, Union

from google.api_core.page_iterator import Iterator
from google.cloud.bigquery.table import TableListItem  # type: ignore

from authz_analyzer.datastores.bigquery.policy_tree import DatasetPolicyNode, PolicyNode, TableIamPolicyNode
from authz_analyzer.datastores.bigquery.service import BigQueryService
from authz_analyzer.models.model import Asset, AuthzEntry, AuthzPathElement, Identity, PermissionLevel
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import BaseWriter
from authz_analyzer.writers.base_writers import DEFAULT_OUTPUT_FILE, OutputFormat
from authz_analyzer.writers.get_writers import get_writer


class Member(TypedDict):
    role: str
    principal: str


@dataclass
class BigQueryAuthzAnalyzer:
    logger: Logger
    service: BigQueryService
    writer: BaseWriter

    @classmethod
    def connect(
        cls,
        project_id: str,
        logger: Optional[Logger] = None,
        output_format: OutputFormat = OutputFormat.Csv,
        output_path: Union[Path, str] = Path.cwd() / DEFAULT_OUTPUT_FILE,
    ):
        writer = get_writer(filename=output_path, format=output_format)
        if logger is None:
            logger = get_logger(False)
        return cls(logger, BigQueryService.load(project_id), writer=writer)

    def run(self):
        """Read all tables in all datasets and calculate authz paths"""
        project_node = self.service.lookup_project()
        for dataset_id in self.service.list_datasets():
            dataset = self.service.get_dataset(dataset_id)
            dataset_node = DatasetPolicyNode(dataset)
            dataset_node.set_parent(project_node)
            tables: Iterator = self.service.list_tables(dataset_id)
            table: TableListItem
            for table in tables:
                fq_table_id = f"{table.project}.{table.dataset_id}.{table.table_id}"  # type: ignore
                table_iam = self.service.get_table_policy(table.reference)
                name: str = table.table_id  # type: ignore
                table_node = TableIamPolicyNode(fq_table_id, name, table_iam)
                table_node.set_parent(dataset_node)
                self._calc(Asset(fq_table_id, type="table"), table_node, [])

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
            permissions = [PermissionLevel.Read, PermissionLevel.Write, PermissionLevel.Full]
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
                ref_node = self.service.lookup_ref(member["principal"])
                if ref_node is None:
                    self.logger.error("Unable to find ref_node for member %s", member)
                    continue
                note = "{} references {} {} with permission {}".format(
                    node.type, ref_node.type.lower(), ref_node.name, permission
                )
                self._add_to_path(path, node, note)
                self._calc(fq_table_id, ref_node, path, permissions=[permission])
                path.pop()

        # Finally, go to the parent and get the inherited permissions
        if node.parent is None:
            return
        self._goto_parent(fq_table_id, node, path, permissions)

    def _goto_parent(
        self, fq_table_id: Asset, node: PolicyNode, path: List[AuthzPathElement], permissions: List[PermissionLevel]
    ):
        note = f"{node.type} is included in {node.parent.type.lower()} {node.parent.name}"  # type: ignore
        self._add_to_path(path, node, note)
        self._calc(fq_table_id, node.parent, path, permissions)  # type: ignore
        path.pop()

    def _add_to_path(self, path: List[AuthzPathElement], node: PolicyNode, note: str):
        self.logger.debug("Adding %s %s to path", node.type, node.name)
        path.append(AuthzPathElement(node.id, node.name, node.type, note))

    def _report_permission(
        self,
        fq_table_id: Asset,
        node: PolicyNode,
        member: Member,
        permission: PermissionLevel,
        path: List[AuthzPathElement],
    ):
        principal = member["principal"]
        role = member["role"]
        note = f"{principal} has role {role}"
        self._add_to_path(path, node, note)
        reversed_path = list(reversed(path))
        try:
            (member_type, member_name) = principal.split(":")
        except ValueError:
            member_type = "user"
            member_name = principal
        identity = Identity(id=principal, type=member_type, name=member_name)
        authz = AuthzEntry(fq_table_id, path=reversed_path, identity=identity, permission=permission)
        self.writer.write_entry(authz)
        path.pop()
