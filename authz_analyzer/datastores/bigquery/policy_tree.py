from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, TypedDict

from google.api_core.iam import Policy
from google.cloud.bigquery.dataset import Dataset  # type: ignore

from authz_analyzer.models.model import AuthzPathElementType, IdentityType, PermissionLevel

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

READ_PERMISSIONS = {"bigquery.dataPolicies.maskedGet", "bigquery.tables.getData"}
WRITE_PERMISSIONS = {
    "bigquery.dataPolicies.maskedSet",
    "bigquery.tables.delete",
    "bigquery.tables.restoreSnapshot",
    "bigquery.tables.updateData",
    "bigquery.transfers.update",
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
class Member:
    role: str
    name: str
    type: IdentityType


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
class AuthzBigQueryBinding:
    role: str
    members: List[str]


@dataclass
class AuthzBigQueryPolicy:
    bindings: List[AuthzBigQueryBinding]


@dataclass
class PolicyNode:
    id: str
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
        self.parent = parent

    def add_member(self, member: str, permission: PermissionLevel, role: str, role_type: str):
        parsed_member = Member(role=role, name=member, type=IDENTITY_TYPE_MAP[role_type])
        self.permissions[permission].append(parsed_member)

    def get_members(self, permission: PermissionLevel):
        return self.permissions[permission]

    def add_reference(self, reference: str, permission: PermissionLevel, role: str, role_type: str):
        parsed_member = Member(role=role, name=reference, type=IDENTITY_TYPE_MAP[role_type])
        self.references[permission].append(parsed_member)

    def get_references(self, permission: PermissionLevel):
        return self.references[permission]

    def __repr__(self):
        return """%s:
    Parent: %s
    Permissions:
        - READ: %s
        - WRITE: %s
        - FULL: %s
    References:
        - READ: %s
        - WRITE: %s
        - FULL: %s
         """ % (
            self.name,
            self.parent,
            self.get_members(PermissionLevel.READ),
            self.get_members(PermissionLevel.WRITE),
            self.get_members(PermissionLevel.FULL),
            self.get_references(PermissionLevel.READ),
            self.get_references(PermissionLevel.WRITE),
            self.get_references(PermissionLevel.FULL),
        )


class IamPolicyNode(PolicyNode):
    def __init__(
        self,
        policy_id: str,
        name: str,
        policy_type: str,
        policy: Policy,
        resolve_permission_callback: Callable[[str], Optional[PermissionLevel]],
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
            role = binding.role
            permission = ROLE_TO_PERMISSION.get(role)
            if permission is None:
                permission = resolve_permission_callback(role)
            if permission is None:
                continue  # Role doesn't have permission to big query
            member: str
            for member in binding.members:
                member_type, member_name = member.split(":")
                super().add_member(member_name, permission, role, member_type)


class TableIamPolicyNode(PolicyNode):
    def __init__(
        self,
        table_id: str,
        name: str,
        policy: Policy,
        resolve_permission_callback: Callable[[str], Optional[PermissionLevel]],
    ):
        """Represents a table IAM policy.

        Args:
            table_id (str): The ID of the table
            name (str): table name
            policy (Policy): BigQuery table IAM policy object as presented by the GCP
            resolve_permission_callback (Callable[[str], Optional[PermissionLevel]]): Resolve permission level from role, when BigQuery is configured with custom roles.
        """
        super().__init__(table_id, name, "TABLE")
        binding: GcpBindingDict
        for binding in policy.bindings:  # type: ignore
            role = binding["role"]
            permission = ROLE_TO_PERMISSION.get(role, resolve_permission_callback(role))
            if permission is None:
                continue  # Role doesn't have permission to big query
            for member in binding["members"]:
                member_type, member_name = member.split(":")
                super().add_member(member_name, permission, role, member_type)


class DatasetPolicyNode(PolicyNode):
    def __init__(self, dataset: Dataset, resolve_permission_callback: Callable[[str], Optional[PermissionLevel]]):
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
                permission = resolve_permission_callback(role)
            if permission is None:
                continue  # Role doesn't have permission to big query
            super().add_member(entry.entity_id, permission, entry.role, entry.entity_type)  # type: ignore
