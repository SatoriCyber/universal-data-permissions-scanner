from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional

from aws_ptrp.iam.policy.policy_document import PolicyDocument, PolicyDocumentCtx
from aws_ptrp.principals import Principal, PrincipalBase
from aws_ptrp.ptrp_models.ptrp_model import (
    AwsPrincipal,
    AwsPtrpNodeNote,
    AwsPtrpNoteType,
    AwsPtrpPathNode,
    AwsPtrpPathNodeType,
    AwsPtrpResource,
    AwsPtrpResourceType,
)
from aws_ptrp.services import MethodOnStmtActionsResultType, ServiceResourceBase, ServiceResourceType


class NodeBase(ABC):
    @abstractmethod
    def get_node_arn(self) -> str:
        pass

    @abstractmethod
    def get_node_name(self) -> str:
        pass

    def __eq__(self, other):
        return self.get_node_arn() == other.get_node_arn() and self.get_node_name() == other.get_node_name()

    def __hash__(self):
        return hash(self.get_node_arn()) + hash(self.get_node_name())


class NodeNoteType(Enum):
    POLICY_STMT_DENY_WITH_CONDITION = auto()
    POLICY_STMT_SKIPPING_DENY_WITH_S3_NOT_RESOURCE = auto()
    IAM_IDENTITY_CENTER_USER_DESCRIPTION = auto()

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
        elif self.note_type == NodeNoteType.POLICY_STMT_SKIPPING_DENY_WITH_S3_NOT_RESOURCE:
            return AwsPtrpNodeNote(
                note=self.note, note_type=AwsPtrpNoteType.POLICY_STMT_SKIPPING_DENY_WITH_S3_NOT_RESOURCE
            )
        elif self.note_type == NodeNoteType.IAM_IDENTITY_CENTER_USER_DESCRIPTION:
            return AwsPtrpNodeNote(note=self.note, note_type=AwsPtrpNoteType.IAM_IDENTITY_CENTER_USER_DESCRIPTION)
        else:
            assert False  # should not get here, unknown enum value

    def __hash__(self) -> int:
        return hash(self.note_type) + hash(self.note)

    def __eq__(self, other):
        return self.note_type == other.note_type and self.note == other.note

    @classmethod
    def from_stmt_info_and_action_stmt_result_type(
        cls,
        stmt_name: str,
        policy_name: str,
        attached_to_other_node_arn: str,
        service_name: str,
        action_stmt_result_type: MethodOnStmtActionsResultType,
    ) -> Optional['NodeNote']:
        if action_stmt_result_type == MethodOnStmtActionsResultType.IGNORE_METHOD_DIFFERENCE_CONDITION_EXISTS:
            return cls(
                note_type=NodeNoteType.POLICY_STMT_DENY_WITH_CONDITION,
                note=f"{stmt_name}{policy_name}{attached_to_other_node_arn} has deny with condition for {service_name} service",
            )
        elif (
            action_stmt_result_type
            == MethodOnStmtActionsResultType.IGNORE_METHOD_DIFFERENCE_WITH_S3_NOT_RESOURCE_OBJECT_REGEX
        ):
            return cls(
                note_type=NodeNoteType.POLICY_STMT_SKIPPING_DENY_WITH_S3_NOT_RESOURCE,
                note=f"{stmt_name}{policy_name}{attached_to_other_node_arn} has deny which might not applied for {service_name} service, due to the use of 'NotResource' with the object regex",
            )
        else:
            return None

    @classmethod
    def from_user_and_identity_center_instance_info(
        cls,
        user_name: str,
        identity_center_instance_arn: str,
        identity_center_account_id: str,
        identity_center_region: str,
    ) -> 'NodeNote':
        return cls(
            note_type=NodeNoteType.IAM_IDENTITY_CENTER_USER_DESCRIPTION,
            note=f"{user_name} is a member of identity center instance {identity_center_instance_arn}, which is configured in account {identity_center_account_id}, region {identity_center_region}",
        )


class NodeNotesGetter(ABC):
    @abstractmethod
    def get_node_notes(self, node_base: NodeBase) -> List[NodeNote]:
        pass

    @abstractmethod
    def get_aws_ptrp_node_notes(self, node_base: NodeBase) -> List[AwsPtrpNodeNote]:
        pass


class PathNodeBase(NodeBase):
    @abstractmethod
    def get_path_type(self) -> AwsPtrpPathNodeType:
        pass


class PoliciesNodeBase(NodeBase):
    @abstractmethod
    def get_attached_policies_arn(self) -> List[str]:
        pass

    @abstractmethod
    def get_inline_policies_ctx(self) -> List[PolicyDocumentCtx]:
        pass


class PrincipalNodeBase(PrincipalBase, NodeBase):
    @abstractmethod
    def get_stmt_principal(self) -> Principal:
        pass

    # PrincipalBase
    def get_principal(self) -> Principal:
        return self.get_stmt_principal()


class PrincipalAndPoliciesNodeBase(PrincipalNodeBase, PoliciesNodeBase):
    pass
    # def get_permission_boundary(self) -> Optional[PolicyDocument]:
    #     return None

    # def get_session_policies(self) -> List[PolicyDocument]:
    #     return []


@dataclass
class PathPermissionSetNodeBase(PathNodeBase):
    pass


@dataclass
class PathPermissionSetNode(PathPermissionSetNodeBase):
    base: PathPermissionSetNodeBase

    def get_ptrp_path_node(self, nodes_notes_getter: NodeNotesGetter) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.base.get_node_arn(),
            name=self.base.get_node_name(),
            type=self.base.get_path_type(),
            notes=nodes_notes_getter.get_aws_ptrp_node_notes(self),
        )

    def __repr__(self):
        return f"PathPermissionSetNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeBase
    def get_node_arn(self) -> str:
        return self.base.get_node_arn()

    def get_node_name(self) -> str:
        return f"{self.base.get_node_name()}"

    def get_path_type(self) -> AwsPtrpPathNodeType:
        return self.base.get_path_type()


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
class PrincipalAndPoliciesNode(PrincipalAndPoliciesNodeBase):
    base: PrincipalAndPoliciesNodeBase
    additional_policies_bases: List[PoliciesNodeBase] = field(default_factory=list)

    def get_principal_to_report(self, nodes_notes_getter: NodeNotesGetter) -> AwsPrincipal:
        principal_to_report: Principal = self.base.get_stmt_principal()
        return AwsPrincipal(
            arn=principal_to_report.get_arn(),
            type=principal_to_report.principal_type,
            name=principal_to_report.get_name(),
            notes=nodes_notes_getter.get_aws_ptrp_node_notes(self),
        )

    def __repr__(self):
        return f"PrincipalAndPoliciesNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeBase
    def get_node_arn(self) -> str:
        return self.base.get_stmt_principal().get_arn()

    def get_node_name(self) -> str:
        return self.base.get_stmt_principal().get_name()

    # PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return self.base.get_stmt_principal()

    # PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        ret = self.base.get_attached_policies_arn()
        for additional_policies_base in self.additional_policies_bases:
            ret.extend(additional_policies_base.get_attached_policies_arn())
        return ret

    def get_inline_policies_ctx(self) -> List[PolicyDocumentCtx]:
        ret = self.base.get_inline_policies_ctx()
        for additional_policies_base in self.additional_policies_bases:
            ret.extend(additional_policies_base.get_inline_policies_ctx())
        return ret


class PathUserGroupNodeBase(PathNodeBase, PoliciesNodeBase):
    pass


@dataclass
class PathUserGroupNode(PathNodeBase):
    base: PathUserGroupNodeBase

    def get_ptrp_path_node(self, nodes_notes_getter: NodeNotesGetter) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.base.get_node_arn(),
            name=self.base.get_node_name(),
            type=self.base.get_path_type(),
            notes=nodes_notes_getter.get_aws_ptrp_node_notes(self),
        )

    def __repr__(self):
        return f"PathUserGroupNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeBase
    def get_node_arn(self) -> str:
        return self.base.get_node_arn()

    def get_node_name(self) -> str:
        return self.base.get_node_name()

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return self.base.get_path_type()


@dataclass
class PathRoleNode(PathRoleNodeBase):
    base: PathRoleNodeBase

    def get_ptrp_path_node(self, nodes_notes_getter: NodeNotesGetter) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.base.get_node_arn(),
            name=self.base.get_node_name(),
            type=self.base.get_path_type(),
            notes=nodes_notes_getter.get_aws_ptrp_node_notes(self),
        )

    def __repr__(self):
        return f"PathRoleNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeBase
    def get_node_arn(self) -> str:
        return self.base.get_node_arn()

    def get_node_name(self) -> str:
        return self.base.get_node_name()

    # PathRoleNodeBase
    def get_service_resource(self) -> ServiceResourceBase:
        return self.base.get_service_resource()

    # PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return self.base.get_stmt_principal()

    # PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.base.get_attached_policies_arn()

    def get_inline_policies_ctx(self) -> List[PolicyDocumentCtx]:
        return self.base.get_inline_policies_ctx()

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return self.base.get_path_type()


@dataclass
class PathFederatedPrincipalNode(PathFederatedPrincipalNodeBase):
    base: PathFederatedPrincipalNodeBase

    def get_ptrp_path_node(self, nodes_notes_getter: NodeNotesGetter) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.base.get_node_arn(),
            name=self.base.get_node_name(),
            type=self.base.get_path_type(),
            notes=nodes_notes_getter.get_aws_ptrp_node_notes(self),
        )

    def __repr__(self):
        return f"PathFederatedPrincipalNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeBase
    def get_node_arn(self) -> str:
        return self.base.get_node_arn()

    def get_node_name(self) -> str:
        return self.base.get_node_name()

    # PathFederatedPrincipalNodeBase
    def get_service_resource(self) -> ServiceResourceBase:
        return self.base.get_service_resource()

    # PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return self.base.get_stmt_principal()

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return self.base.get_path_type()


@dataclass
class PathPolicyNode(PathPolicyNodeBase):
    path_element_type: AwsPtrpPathNodeType
    policy_document_ctx: PolicyDocumentCtx
    is_resource_based_policy: bool

    def get_ptrp_path_node(self, nodes_notes_getter: NodeNotesGetter) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.policy_document_ctx.parent_arn,
            name=self.policy_document_ctx.policy_name,
            type=self.path_element_type,
            notes=nodes_notes_getter.get_aws_ptrp_node_notes(self),
        )

    def __repr__(self):
        if self.is_resource_based_policy:
            policy_type = "resource-based"
        else:
            policy_type = "identity-based"
        return f"PathPolicyNode(Arn: {self.policy_document_ctx.parent_arn}, Name: {self.policy_document_ctx.policy_name}, PolicyType: {policy_type})"

    def __eq__(self, other):
        return (
            self.policy_document_ctx.parent_arn == other.policy_document_ctx.parent_arn
            and self.policy_document_ctx.policy_name == other.policy_document_ctx.policy_name
        )

    def __hash__(self):
        return hash(self.policy_document_ctx.parent_arn) + hash(self.policy_document_ctx.policy_name)

    # NodeBase
    def get_node_arn(self) -> str:
        return self.policy_document_ctx.parent_arn

    def get_node_name(self) -> str:
        return self.policy_document_ctx.policy_name

    # PathPolicyNodeBase
    def get_policy(self) -> PolicyDocument:
        return self.policy_document_ctx.policy_document

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return self.path_element_type


class ResourceNodeBase(ServiceResourceBase):
    @abstractmethod
    def get_ptrp_resource_type(self) -> AwsPtrpResourceType:
        pass


@dataclass
class ResourceNode(ResourceNodeBase, NodeBase):
    base: ResourceNodeBase
    service_resource_type: ServiceResourceType

    def get_ptrp_resource_to_report(self, nodes_notes_getter: NodeNotesGetter) -> AwsPtrpResource:
        return AwsPtrpResource(
            name=self.base.get_resource_name(),
            type=self.base.get_ptrp_resource_type(),
            notes=nodes_notes_getter.get_aws_ptrp_node_notes(self),
        )

    def __repr__(self):
        return f"ResourceNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

    # NodeBase
    def get_node_arn(self) -> str:
        return self.base.get_resource_arn()

    def get_node_name(self) -> str:
        # Adding __ResourceNode__ just for ResourceNodeBase
        # to distinguish between resource node to target node(resource-based policy) - NodeBase __eq__
        return f"__ResourceNode__{self.base.get_resource_name()}"

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
