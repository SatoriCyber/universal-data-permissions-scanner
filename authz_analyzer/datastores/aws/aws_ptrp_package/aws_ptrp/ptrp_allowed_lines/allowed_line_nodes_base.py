from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Tuple

from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.principals import Principal
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpPathNode, AwsPtrpPathNodeType, AwsPtrpResourceType
from aws_ptrp.services import ServiceResourceBase, ServiceResourceType


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


class PrincipalNodeBase:
    @abstractmethod
    def get_stmt_principal(self) -> Principal:
        pass


class PrincipalAndPoliciesNodeBase(PrincipalNodeBase, PoliciesNodeBase):
    pass
    # def get_permission_boundary(self) -> Optional[PolicyDocument]:
    #     return None

    # def get_session_policies(self) -> List[PolicyDocument]:
    #     return []


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


class PathUserGroupNodeBase(PoliciesNodeBase, PathNodeBase):
    pass


@dataclass
class PathUserGroupNode(PathUserGroupNodeBase):
    base: PathUserGroupNodeBase
    note: str

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.base.get_path_arn(),
            name=self.base.get_path_name(),
            type=self.base.get_path_type(),
            note=self.note,
        )

    def __repr__(self):
        return f"PathUserGroupNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

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
class PathRoleNode(PathRoleNodeBase):
    base: PathRoleNodeBase
    note: str

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.base.get_path_arn(),
            name=self.base.get_path_name(),
            type=self.base.get_path_type(),
            note=self.note,
        )

    def __repr__(self):
        return f"PathRoleNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

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
class PathFederatedPrincipalNode(PathFederatedPrincipalNodeBase):
    base: PathFederatedPrincipalNodeBase
    note: str

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.base.get_path_arn(),
            name=self.base.get_path_name(),
            type=self.base.get_path_type(),
            note=self.note,
        )

    def __repr__(self):
        return f"PathFederatedPrincipalNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)

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
class PathPolicyNode(PathPolicyNodeBase):
    path_element_type: AwsPtrpPathNodeType
    path_arn: str
    path_name: str
    policy_document: PolicyDocument
    is_resource_based_policy: bool
    note: str

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.path_arn,
            name=self.path_name,
            type=self.path_element_type,
            note=self.note,
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
class ResourceNode:
    base: ResourceNodeBase
    service_resource_type: ServiceResourceType
    note: str

    def __repr__(self):
        return f"ResourceNode({self.base.__repr__()})"

    def __eq__(self, other):
        return self.base == other.base

    def __hash__(self):
        return hash(self.base)
