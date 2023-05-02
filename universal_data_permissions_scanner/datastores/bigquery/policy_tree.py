from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, TypedDict

from google.api_core.iam import Policy
from google.cloud.bigquery.dataset import Dataset  # type: ignore

from universal_data_permissions_scanner.models.model import AuthzPathElementType, IdentityType, PermissionLevel

ROLE_TO_PERMISSION = {
    "roles/viewer": PermissionLevel.READ,
    "roles/editor": PermissionLevel.WRITE,
    "roles/owner": PermissionLevel.FULL,
    "roles/bigquery.admin": PermissionLevel.FULL,
    "roles/bigquery.dataEditor": PermissionLevel.WRITE,
    "roles/bigquery.dataOwner": PermissionLevel.FULL,
    "roles/bigquery.dataViewer": PermissionLevel.READ,
    "roles/bigquery.filteredDataViewer": PermissionLevel.READ,
    "roles/bigquery.jobUser": PermissionLevel.WRITE,
    "roles/bigquery.user": PermissionLevel.READ,
    "roles/bigquerydatapolicy.maskedReader": PermissionLevel.READ,
    "OWNER": PermissionLevel.FULL,
    "WRITER": PermissionLevel.WRITE,
    "READER": PermissionLevel.READ,
}

READ_PERMISSIONS = {
    "bigquery.dataPolicies.maskedGet",
    "bigquery.tables.getData",
    "bigquery.jobs.get",
    "bigquery.models.getData",
    "bigquery.models.export",
    "bigquery.readsessions.getData",
    "bigquery.rowAccessPolicies.getFilteredData",
    "bigquery.tables.export",
}
WRITE_PERMISSIONS = {
    "bigquery.dataPolicies.maskedSet",
    "bigquery.tables.delete",
    "bigquery.tables.restoreSnapshot",
    "bigquery.tables.updateData",
    "bigquery.transfers.update",
    "bigquery.jobs.create",
    "bigquery.jobs.update",
    "bigquery.models.updateData",
    "bigquery.tables.deleteSnapshot",
    "bigquery.models.delete",
}


GRANTED_BY_TO_PATHZ_ELEMENT = {
    "table": AuthzPathElementType.TABLE,
    "TABLE": AuthzPathElementType.TABLE,
    "DATASET": AuthzPathElementType.DATASET,
    "dataset": AuthzPathElementType.DATASET,
    "project": AuthzPathElementType.PROJECT,
    "PROJECT": AuthzPathElementType.PROJECT,
    "folder": AuthzPathElementType.FOLDER,
    "FOLDER": AuthzPathElementType.FOLDER,
    "organization": AuthzPathElementType.ORGANIZATION,
    "ORGANIZATION": AuthzPathElementType.ORGANIZATION,
}

IDENTITY_TYPE_MAP = {
    "userByEmail": IdentityType.USER,
    "user": IdentityType.USER,
    "serviceAccount": IdentityType.SERVICE_ACCOUNT,
    "group": IdentityType.GROUP,
    "domain": IdentityType.CLOUD_IDENTITY_DOMAIN,
    "allAuthenticatedUsers": IdentityType.WORKSPACE_ACCOUNT,
}


@dataclass
class CustomPermission:
    """Defines a GCP permission, which is a combination of a role and a permission level."""

    db_permissions: List[str]
    permission: PermissionLevel


@dataclass
class Member:
    """Defines a GCP member, which is a combination of a role and an identity."""

    role: str
    name: str
    type: IdentityType
    original_identity_type: str
    db_permissions: List[str] = field(default_factory=list)


@dataclass
class GcpBinding:
    """GCP Binding

    Attributes:
        role (str): Role that is assigned to members.
        members (List[str]): Specifies the identities associated to this binding.
        condition (Dict[str, str]): Specifies a condition under which this binding will apply.
        title (str): Title for the condition.
        description (Optional[str]): Description of the condition.
        expression (Any): A CEL expression.
    """

    role: str
    members: Set[str]
    condition: Dict[str, str]
    title: str
    description: Optional[str]
    expression: Any


@dataclass
class GcpBindingDict(TypedDict):
    """GCP Binding as a dict object

    Attributes:
        role (str): Role that is assigned to members.
        members (List[str]): Specifies the identities associated to this binding.
        condition (Dict[str, str]): Specifies a condition under which this binding will apply.
        title (str): Title for the condition.
        description (Optional[str]): Description of the condition.
        expression (Any): A CEL expression.
    """

    role: str
    members: Set[str]
    condition: Dict[str, str]
    title: str
    description: Optional[str]
    expression: Any


@dataclass
class PolicyNode:
    """Base class for a policy node, other policies node inherit from this class."""

    id: str  # pylint: disable=invalid-name
    name: str
    type: str
    parent: Optional[PolicyNode] = None
    permissions: Dict[PermissionLevel, List[Member]] = field(
        default_factory=lambda: {
            PermissionLevel.READ: [],
            PermissionLevel.WRITE: [],
            PermissionLevel.FULL: [],
            PermissionLevel.UNKNOWN: [],
        }
    )
    references: Dict[PermissionLevel, List[Member]] = field(
        default_factory=lambda: {
            PermissionLevel.READ: [],
            PermissionLevel.WRITE: [],
            PermissionLevel.FULL: [],
            PermissionLevel.UNKNOWN: [],
        }
    )

    def set_parent(self, parent: PolicyNode):
        """Defines the parent of the node, for example a dataset is the parent of a table."""
        self.parent = parent

    def add_member(
        self,
        member: str,
        permission: PermissionLevel,
        role: str,
        member_type: str,
        db_permissions: Optional[List[str]] = None,
    ):
        """Add a member of the node, for example user X have access to project Y with role Z.

        Args:
            member (str): The identity of the member, for example USER_1
            permission (PermissionLevel): What permission he has, for example READ
            role (str): The role that granted the permission.
            member_type (str): Type of the member, for example user, group, service account.
        """
        if db_permissions is None:
            db_permissions = []
        parsed_member = Member(
            role=role,
            name=member,
            type=IDENTITY_TYPE_MAP[member_type],
            db_permissions=db_permissions,
            original_identity_type=member_type,
        )
        self.permissions[permission].append(parsed_member)

    def get_members(self, permission: PermissionLevel):
        """Get all member for specific permission, for example all users that have READ access for project Y.

        Args:
            permission (PermissionLevel): Permission level, for example READ

        Returns:
            List[Member]: all members who has this permission.
        """
        return self.permissions[permission]

    def add_reference(self, reference: str, permission: PermissionLevel, role: str, role_type: str):
        parsed_member = Member(
            role=role, name=reference, type=IDENTITY_TYPE_MAP[role_type], original_identity_type=role_type
        )
        self.references[permission].append(parsed_member)

    def get_references(self, permission: PermissionLevel):
        return self.references[permission]

    def __repr__(self):
        return f"""{self.name}:
    Parent: {self.parent}
    Permissions:
        - READ: {self.get_members(PermissionLevel.READ)}
        - WRITE: {self.get_members(PermissionLevel.WRITE)}
        - FULL: {self.get_members(PermissionLevel.FULL)}
    References:
        - READ: {self.get_references(PermissionLevel.READ)}
        - WRITE: {self.get_references(PermissionLevel.WRITE)}
        - FULL: {self.get_references(PermissionLevel.FULL)}"
        """


class IamPolicyNode(PolicyNode):
    """Represents a GCP IAM policy node, for example a project, folder, organization."""

    def __init__(
        self,
        policy_id: str,
        name: str,
        policy_type: str,
        policy: Policy,
        resolve_permission_callback: Callable[[str], Optional[CustomPermission]],
    ):
        """Represents a GCP IAM policy node, Project, Folder, Organization, etc.

        Args:
            policy_id (str): The id of the policy
            name (str): The name of the policy
            policy_type (str): The policy type, for example: project, folder, organization
            policy (Policy): Policy object as defined by google.cloud.iam.policy.Policy
            resolve_permission_callback (Callable[[str], Optional[PermissionLevel]]): Resolve permission level from role, when BigQuery is configured with custom roles.
        """
        super().__init__(policy_id, name, policy_type)
        binding: GcpBinding
        for binding in policy.bindings:  # type: ignore
            db_permissions: List[str] = []
            role = binding.role
            permission = ROLE_TO_PERMISSION.get(role)
            if permission is None:
                custom_permission = resolve_permission_callback(role)
                if custom_permission is not None:
                    permission = custom_permission.permission
                    db_permissions = custom_permission.db_permissions
            if permission is None:
                continue  # Role doesn't have permission to big query
            member: str
            for member in binding.members:
                if member.startswith("deleted:"):
                    continue
                member_type, member_name = member.split(":")
                super().add_member(member_name, permission, role, member_type, db_permissions)


class TableIamPolicyNode(PolicyNode):
    """Represents a BigQuery table IAM policy."""

    def __init__(
        self,
        table_id: str,
        name: str,
        policy: Policy,
        resolve_permission_callback: Callable[[str], Optional[CustomPermission]],
    ):
        """Represents a table IAM policy.

        Args:
            table_id (str): The ID of the table
            name (str): table name
            policy (Policy): BigQuery table IAM policy object as presented by the GCP
            resolve_permission_callback (Callable[[str], Optional[CustomPermission]]): Resolve permission level from role, when BigQuery is configured with custom roles.
        """
        super().__init__(table_id, name, "TABLE")
        binding: GcpBindingDict
        for binding in policy.bindings:  # type: ignore
            db_permissions = []
            role = binding["role"]
            permission = ROLE_TO_PERMISSION.get(role)
            if permission is None:
                custom_permission = resolve_permission_callback(role)
                if custom_permission is not None:
                    permission = custom_permission.permission
                    db_permissions = custom_permission.db_permissions
            if permission is None:
                continue  # Role doesn't have permission to big query
            for member in binding["members"]:
                member_type, member_name = member.split(":")
                super().add_member(member_name, permission, role, member_type, db_permissions)


class DatasetPolicyNode(PolicyNode):
    """Represents a BigQuery dataset policy node."""

    def __init__(self, dataset: Dataset, resolve_permission_callback: Callable[[str], Optional[CustomPermission]]):
        """Represent a BigQuery dataset policy node.

        Args:
            dataset (Dataset): A BigQuery dataset object.
            resolve_permission_callback (Callable[[str], Optional[PermissionLevel]]): Resolve permission level from role, when BigQuery is configured with custom roles.
        """
        dataset_id: str = dataset.dataset_id  # type: ignore
        friendly_name: Optional[str] = dataset.friendly_name  # type: ignore
        name: str = friendly_name if friendly_name is not None else dataset_id  # type: ignore

        super().__init__(dataset_id, name, "DATASET")  # type: ignore

        for entry in dataset.access_entries:
            db_permissions = []
            if entry.entity_type == "specialGroup" and entry.entity_id in [  # type: ignore
                "projectReaders",
                "projectWriters",
                "projectOwners",
            ]:
                # These specialGroup permissions are legacy, because the dataset always inherits
                # permissions from its parent project.
                continue
            role: str = entry.role  # type: ignore
            permission = ROLE_TO_PERMISSION.get(role)
            if permission is None:
                custom_permission = resolve_permission_callback(role)
                if custom_permission is not None:
                    permission = custom_permission.permission
                    db_permissions = custom_permission.db_permissions
            if permission is None:
                continue  # Role doesn't have permission to big query
            super().add_member(entry.entity_id, permission, entry.role, entry.entity_type, db_permissions)  # type: ignore
