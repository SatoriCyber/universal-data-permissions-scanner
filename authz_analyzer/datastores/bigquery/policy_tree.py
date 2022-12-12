from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from google.cloud.bigquery.dataset import Dataset #type: ignore

from google.api_core.iam import Policy

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
}



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
    permissions: Dict[PermissionLevel, List[Dict[str, str]]] = field(default_factory=lambda: {PermissionLevel.Read: [], PermissionLevel.Write: [], PermissionLevel.Full: []})
    references: Dict[PermissionLevel, List[Dict[str, str]]] = field(default_factory=lambda: {PermissionLevel.Read: [], PermissionLevel.Write: [], PermissionLevel.Full: []})

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
        for binding in policy.bindings: #type: ignore
            role: str = binding.role #type: ignore
            if role is not None:
                permission = ROLE_TO_PERMISSION.get(role)
                if permission is not None:
                    member: str
                    for member in binding.members: #type: ignore
                        super().add_member(member, permission, role)


class TableIamPolicyNode(PolicyNode):
    def __init__(self, table_id: str, name: str, policy: Policy):
        super().__init__(table_id, name, "TABLE")
        binding: Dict[str, str]
        for binding in policy.bindings: #type: ignore
            role: str = binding.role #type: ignore
            if role is not None:
                permission = ROLE_TO_PERMISSION.get(role)
                if permission is not None:
                    member: str
                    for member in binding.members: #type: ignore
                        if member.startswith("user:"):
                            super().add_member(member, permission, role)
                        if member.startswith("serviceAccount:"):
                            super().add_member(member, permission, role)
                        else:
                            super().add_reference(member, permission, role)


class DatasetPolicyNode(PolicyNode):
    def __init__(self, dataset: Dataset):
        dataset_id: str = dataset.dataset_id #type: ignore
        friendly_name: Optional[str] = dataset.friendly_name #type: ignore
        name: str = friendly_name if friendly_name is not None else dataset_id #type: ignore
        
        super().__init__(dataset_id, name, "DATASET") #type: ignore
        
        for entry in dataset.access_entries:
            if entry.entity_type == "user_by_email": #type: ignore
                super().add_member(entry.entity_id, entry.role, entry.role) #type: ignore
            elif entry.entity_type == "specialGroup" and entry.entity_id in [ #type: ignore
                "projectReaders",
                "projectWriters",
                "projectOwners",
            ]:
                # These specialGroup permissions are legacy, because the dataset always inherits
                # permissions from its parent project.
                continue
            else:
                # catch all just so we don't miss stuff
                # TODO - handle groups, domain, all, etc
                super().add_member(entry.entity_id, entry.role, entry.role) #type: ignore
