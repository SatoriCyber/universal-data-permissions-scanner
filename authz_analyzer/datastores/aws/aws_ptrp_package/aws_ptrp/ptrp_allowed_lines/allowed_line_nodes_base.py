from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Iterable, List, Optional, Tuple, Set

from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.principals import Principal
from aws_ptrp.ptrp_models.ptrp_model import (
    AwsPrincipal,
    AwsPtrpNodeNote,
    AwsPtrpNoteType,
    AwsPtrpPathNode,
    AwsPtrpPathNodeType,
    AwsPtrpResource,
    AwsPtrpResourceType,
)
from aws_ptrp.services import ServiceResourceBase, ServiceResourceType


class NodeNoteType(Enum):
    POLICY_STMT_DENY_WITH_CONDITION = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other):
        return self.value == other.value


@dataclass
class NodeNote:
    note_type: NodeNoteType
    note: str

    def to_ptrp_node_note(self) -> AwsPtrpNodeNote:
        if self.note_type == NodeNoteType.POLICY_STMT_DENY_WITH_CONDITION:
            return AwsPtrpNodeNote(note=self.note, note_type=AwsPtrpNoteType.POLICY_STMT_DENY_WITH_CONDITION)
        else:
            assert False  # should not get here, unknown enum value

    def __hash__(self) -> int:
        return hash(self.note_type) + hash(self.note)

    def __eq__(self, other):
        return self.note_type == other.note_type and self.note == other.note


class NodeNoteBase(ABC):
    @abstractmethod
    def get_node_arn(self) -> str:
        pass

    @abstractmethod
    def get_node_name(self) -> str:
        pass

    @abstractmethod
    def add_node_note(self, node_note: NodeNote):
        pass

    @abstractmethod
    def get_node_notes(self) -> Iterable[NodeNote]:
        pass


class PathNodeBase(ABC):
    @abstractmethod
    def get_path_type(self) -> AwsPtrpPathNodeType:
        pass

    @abstractmethod
    def get_path_name(self) -> str:
        pass

    @abstractmethod
    def get_path_arn(self) -> str:
        pass


class PoliciesNodeBase(ABC):
    @abstractmethod
    def get_attached_policies_arn(self) -> List[str]:
        pass

    @abstractmethod
    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        pass


class PoliciesAndNodeNoteBase(PoliciesNodeBase, NodeNoteBase):
    pass


class PrincipalNodeBase(ABC):
    @abstractmethod
    def get_stmt_principal(self) -> Principal:
        pass


class PrincipalAndPoliciesNodeBase(PrincipalNodeBase, PoliciesNodeBase):
    pass
    # def get_permission_boundary(self) -> Optional[PolicyDocument]:
    #     return None

    # def get_session_policies(self) -> List[PolicyDocument]:
    #     return []


class PrincipalAndNodeNoteBase(PrincipalNodeBase, NodeNoteBase):
    pass


class PathRoleNodeBase(PrincipalAndPoliciesNodeBase, PathNodeBase):
    @abstractmethod
    def get_service_resource(self) -> ServiceResourceBase:
        pass


class PathFederatedPrincipalNodeBase(PrincipalNodeBase, PathNodeBase):
    @abstractmethod
    def get_service_resource(self) -> ServiceResourceBase:
        pass


class PathPolicyNodeBase(PathNodeBase):
    @abstractmethod
    def get_policy(self) -> PolicyDocument:
        pass


@dataclass
class PrincipalAndPoliciesNode(PrincipalAndPoliciesNodeBase, PrincipalAndNodeNoteBase, PoliciesAndNodeNoteBase):
    base: PrincipalAndPoliciesNodeBase
    notes: Set[NodeNote] = field(default_factory=set)

    def get_principal_to_report(self) -> AwsPrincipal:
        principal_to_report: Principal = self.base.get_stmt_principal()
        return AwsPrincipal(
            arn=principal_to_report.get_arn(),
            type=principal_to_report.principal_type,
            name=principal_to_report.get_name(),
            notes=[node_node.to_ptrp_node_note() for node_node in self.notes],
        )

    def __repr__(self):
        return f"PrincipalAndPoliciesNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeNoteBase
    def get_node_arn(self) -> str:
        return self.base.get_stmt_principal().get_arn()

    def get_node_name(self) -> str:
        return self.base.get_stmt_principal().get_name()

    def add_node_note(self, node_note: NodeNote):
        self.notes.add(node_note)

    def get_node_notes(self) -> Iterable[NodeNote]:
        return self.notes

    # PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return self.base.get_stmt_principal()

    # PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.base.get_attached_policies_arn()

    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        return self.base.get_inline_policies_and_names()


class PathUserGroupNodeBase(PoliciesNodeBase, PathNodeBase):
    pass


@dataclass
class PathUserGroupNode(PathUserGroupNodeBase, PoliciesAndNodeNoteBase):
    base: PathUserGroupNodeBase
    notes: Set[NodeNote] = field(default_factory=set)

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.base.get_path_arn(),
            name=self.base.get_path_name(),
            type=self.base.get_path_type(),
            notes=[node_node.to_ptrp_node_note() for node_node in self.notes],
        )

    def __repr__(self):
        return f"PathUserGroupNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeNoteBase
    def get_node_arn(self) -> str:
        return self.base.get_path_arn()

    def get_node_name(self) -> str:
        return self.base.get_path_name()

    def add_node_note(self, node_note: NodeNote):
        self.notes.add(node_note)

    def get_node_notes(self) -> Iterable[NodeNote]:
        return self.notes

    # PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.base.get_attached_policies_arn()

    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        return self.base.get_inline_policies_and_names()

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return self.base.get_path_type()

    def get_path_name(self) -> str:
        return self.base.get_path_name()

    def get_path_arn(self) -> str:
        return self.base.get_path_arn()


@dataclass
class PathRoleNode(PathRoleNodeBase, PrincipalAndNodeNoteBase, PoliciesAndNodeNoteBase):
    base: PathRoleNodeBase
    notes: Set[NodeNote] = field(default_factory=set)

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.base.get_path_arn(),
            name=self.base.get_path_name(),
            type=self.base.get_path_type(),
            notes=[node_node.to_ptrp_node_note() for node_node in self.notes],
        )

    def __repr__(self):
        return f"PathRoleNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeNoteBase
    def get_node_arn(self) -> str:
        return self.base.get_path_arn()

    def get_node_name(self) -> str:
        return self.base.get_path_name()

    def add_node_note(self, node_note: NodeNote):
        self.notes.add(node_note)

    def get_node_notes(self) -> Iterable[NodeNote]:
        return self.notes

    # PathRoleNodeBase
    def get_service_resource(self) -> ServiceResourceBase:
        return self.base.get_service_resource()

    # PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return self.base.get_stmt_principal()

    # PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.base.get_attached_policies_arn()

    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        return self.base.get_inline_policies_and_names()

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return self.base.get_path_type()

    def get_path_name(self) -> str:
        return self.base.get_path_name()

    def get_path_arn(self) -> str:
        return self.base.get_path_arn()


@dataclass
class PathFederatedPrincipalNode(PathFederatedPrincipalNodeBase, PrincipalAndNodeNoteBase):
    base: PathFederatedPrincipalNodeBase
    notes: Set[NodeNote] = field(default_factory=set)

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.base.get_path_arn(),
            name=self.base.get_path_name(),
            type=self.base.get_path_type(),
            notes=[node_node.to_ptrp_node_note() for node_node in self.notes],
        )

    def __repr__(self):
        return f"PathFederatedPrincipalNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeNoteBase
    def get_node_arn(self) -> str:
        return self.base.get_path_arn()

    def get_node_name(self) -> str:
        return self.base.get_path_name()

    def add_node_note(self, node_note: NodeNote):
        self.notes.add(node_note)

    def get_node_notes(self) -> Iterable[NodeNote]:
        return self.notes

    # PathFederatedPrincipalNodeBase
    def get_service_resource(self) -> ServiceResourceBase:
        return self.base.get_service_resource()

    # PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return self.base.get_stmt_principal()

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return self.base.get_path_type()

    def get_path_name(self) -> str:
        return self.base.get_path_name()

    def get_path_arn(self) -> str:
        return self.base.get_path_arn()


@dataclass
class PathPolicyNode(PathPolicyNodeBase, NodeNoteBase):
    path_element_type: AwsPtrpPathNodeType
    path_arn: str
    path_name: str
    policy_document: PolicyDocument
    is_resource_based_policy: bool
    notes: Set[NodeNote] = field(default_factory=set)

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.path_arn,
            name=self.path_name,
            type=self.path_element_type,
            notes=[node_node.to_ptrp_node_note() for node_node in self.notes],
        )

    def __repr__(self):
        if self.is_resource_based_policy:
            policy_type = "resource-based"
        else:
            policy_type = "identity-based"
        return f"PathPolicyNode(Arn: {self.path_arn}, Name: {self.path_name}, PolicyType: {policy_type})"

    def __eq__(self, other):
        return self.path_arn == other.path_arn and self.path_name == other.path_name

    def __hash__(self):
        return hash(self.path_arn) + hash(self.path_name)

    # NodeNoteBase
    def get_node_arn(self) -> str:
        return self.get_path_arn()

    def get_node_name(self) -> str:
        return self.get_path_name()

    def add_node_note(self, node_note: NodeNote):
        self.notes.add(node_note)

    def get_node_notes(self) -> Iterable[NodeNote]:
        return self.notes

    # PathPolicyNodeBase
    def get_policy(self) -> PolicyDocument:
        return self.policy_document

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return self.path_element_type

    def get_path_name(self) -> str:
        return self.path_name

    def get_path_arn(self) -> str:
        return self.path_arn


class ResourceNodeBase(ServiceResourceBase):
    @abstractmethod
    def get_ptrp_resource_type(self) -> AwsPtrpResourceType:
        pass


@dataclass
class ResourceNode(ResourceNodeBase, NodeNoteBase):
    base: ResourceNodeBase
    service_resource_type: ServiceResourceType
    notes: Set[NodeNote] = field(default_factory=set)

    def get_ptrp_resource_to_report(self) -> AwsPtrpResource:
        return AwsPtrpResource(
            name=self.base.get_resource_name(),
            type=self.base.get_ptrp_resource_type(),
            notes=[node_node.to_ptrp_node_note() for node_node in self.notes],
        )

    def __repr__(self):
        return f"ResourceNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeNoteBase
    def get_node_arn(self) -> str:
        return self.base.get_resource_arn()

    def get_node_name(self) -> str:
        return self.base.get_resource_name()

    def add_node_note(self, node_note: NodeNote):
        self.notes.add(node_note)

    def get_node_notes(self) -> Iterable[NodeNote]:
        return self.notes

    # ResourceNodeBase
    def get_ptrp_resource_type(self) -> AwsPtrpResourceType:
        return self.base.get_ptrp_resource_type()

    # ServiceResourceBase
    def get_resource_arn(self) -> str:
        return self.base.get_resource_arn()

    def get_resource_name(self) -> str:
        return self.base.get_resource_name()

    def get_resource_policy(self) -> Optional[PolicyDocument]:
        return self.base.get_resource_policy()

    def get_resource_account_id(self) -> str:
        return self.base.get_resource_account_id()
