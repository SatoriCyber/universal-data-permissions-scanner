from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, TypedDict

from google.api_core.iam import Policy
from google.cloud.bigquery.dataset import Dataset  # type: ignore

from authz_analyzer.models.model import PermissionLevel

ROLE_TO_PERMISSION = {
    "roles/viewer": PermissionLevel.Read,
    "roles/editor": PermissionLevel.Write,
    "roles/owner": PermissionLevel.Full,
    "roles/bigquery.admin": PermissionLevel.Full,
    "roles/bigquery.dataEditor": PermissionLevel.Write,
    "roles/bigquery.dataOwner": PermissionLevel.Full,
    "roles/bigquery.dataViewer": PermissionLevel.Read,
    "roles/bigquery.filteredDataViewer": PermissionLevel.Read,
    "roles/bigquery.jobUser": PermissionLevel.Write,
    "roles/bigquery.user": PermissionLevel.Read,
    "roles/bigquerydatapolicy.maskedReader": PermissionLevel.Read,
    "OWNER": PermissionLevel.Full,
    "WRITER": PermissionLevel.Write,
    "READER": PermissionLevel.Read,
}


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
    permissions: Dict[PermissionLevel, List[Dict[str, str]]] = field(
        default_factory=lambda: {
            PermissionLevel.Read: [],
            PermissionLevel.Write: [],
            PermissionLevel.Full: [],
            PermissionLevel.Unknown: [],
        }
    )
    references: Dict[PermissionLevel, List[Dict[str, str]]] = field(
        default_factory=lambda: {
            PermissionLevel.Read: [],
            PermissionLevel.Write: [],
            PermissionLevel.Full: [],
            PermissionLevel.Unknown: [],
        }
    )

    def set_parent(self, parent: PolicyNode):
        self.parent = parent

    def add_member(self, member: str, permission: PermissionLevel, role: str):
        self.permissions[permission].append({"principal": member, "role": role})

    def get_members(self, permission: PermissionLevel):
        return self.permissions[permission]

    def add_reference(self, reference: str, permission: PermissionLevel, role: str):
        self.references[permission].append({"principal": reference, "role": role})

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
            self.get_members(PermissionLevel.Read),
            self.get_members(PermissionLevel.Write),
            self.get_members(PermissionLevel.Full),
            self.get_references(PermissionLevel.Read),
            self.get_references(PermissionLevel.Write),
            self.get_references(PermissionLevel.Full),
        )


class IamPolicyNode(PolicyNode):
    def __init__(self, policy_id: str, name: str, policy_type: str, policy: Policy):
        super().__init__(policy_id, name, policy_type)
        binding: GcpBinding
        for binding in policy.bindings:  # type: ignore
            role = binding.role
            permission = ROLE_TO_PERMISSION.get(role, PermissionLevel.Unknown)
            member: str
            for member in binding.members:
                super().add_member(member, permission, role)


class TableIamPolicyNode(PolicyNode):
    def __init__(self, table_id: str, name: str, policy: Policy):
        super().__init__(table_id, name, "TABLE")
        binding: GcpBindingDict
        for binding in policy.bindings:  # type: ignore
            role = binding["role"]
            permission = ROLE_TO_PERMISSION.get(role, PermissionLevel.Unknown)
            for member in binding["members"]:
                if member.startswith("user:"):
                    super().add_member(member, permission, role)
                elif member.startswith("serviceAccount:"):
                    super().add_member(member, permission, role)
                else:
                    super().add_reference(member, permission, role)


class DatasetPolicyNode(PolicyNode):
    def __init__(self, dataset: Dataset):
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
            if entry.entity_type == "userByEmail":  # type: ignore
                super().add_member(entry.entity_id, ROLE_TO_PERMISSION.get(entry.role, PermissionLevel.Unknown), entry.role)  # type: ignore
            else:
                # catch all just so we don't miss stuff
                # TODO - handle groups, domain, all, etc
                super().add_member(entry.entity_id, ROLE_TO_PERMISSION.get(entry.role, PermissionLevel.Unknown), entry.role)  # type: ignore
