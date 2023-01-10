from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Tuple, Optional

from aws_ptrp.services import ServiceResourceBase
from aws_ptrp.iam.policy.principal import StmtPrincipal
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpPathNodeType, AwsPtrpPathNode, AwsPtrpResourceType


class PrincipalPoliciesNodeBase(ABC):
    @abstractmethod
    def get_attached_policies_arn(self) -> List[str]:
        pass

    @abstractmethod
    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        pass


class PrincipalNodeBase(PrincipalPoliciesNodeBase):
    @abstractmethod
    def get_stmt_principal(self) -> StmtPrincipal:
        pass

    # def get_permission_boundary(self) -> Optional[PolicyDocument]:
    #     return None

    # def get_session_policies(self) -> List[PolicyDocument]:
    #     return []


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


class PathRoleNodeBase(PrincipalNodeBase, PathNodeBase):
    pass


class PathPrincipalPoliciesNodeBase(PrincipalPoliciesNodeBase, PathNodeBase):
    pass


@dataclass
class PathPrincipalPoliciesNode:
    path_principal_policies_base: PathPrincipalPoliciesNodeBase
    note: str

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.path_principal_policies_base.get_path_arn(),
            name=self.path_principal_policies_base.get_path_name(),
            type=self.path_principal_policies_base.get_path_type(),
            note=self.note,
        )

    def __repr__(self):
        return f"PathPrincipalPoliciesNode({self.path_principal_policies_base.__repr__()})"

    def __eq__(self, other):
        return self.path_principal_policies_base.__eq__(other.path_principal_policies_base)

    def __hash__(self):
        return self.path_principal_policies_base.__hash__()


@dataclass
class PathRoleNode:
    path_role_base: PathRoleNodeBase
    note: str

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.path_role_base.get_path_arn(),
            name=self.path_role_base.get_path_name(),
            type=self.path_role_base.get_path_type(),
            note=self.note,
        )

    def __repr__(self):
        return f"PathRoleNode({self.path_role_base.__repr__()})"

    def __eq__(self, other):
        return self.path_role_base.__eq__(other.path_role_base)

    def __hash__(self):
        return self.path_role_base.__hash__()


@dataclass
class TargetPolicyNode:
    path_element_type: AwsPtrpPathNodeType
    path_arn: str
    path_name: str
    policy_document: PolicyDocument
    note: str

    def __repr__(self):
        return f"TargetPolicyNode(Arn: {self.path_arn}, Name: {self.path_name})"

    def __eq__(self, other):
        return self.path_arn == other.path_arn and self.path_name and other.path_name

    def __hash__(self):
        return hash(self.path_arn) + hash(self.path_name)

    def get_ptrp_path_node(self) -> AwsPtrpPathNode:
        return AwsPtrpPathNode(
            arn=self.path_arn,
            name=self.path_name,
            type=self.path_element_type,
            note=self.note,
        )


class ResourceNodeBase(ServiceResourceBase):
    @abstractmethod
    def get_ptrp_resource_type(self) -> AwsPtrpResourceType:
        pass

    @abstractmethod
    def get_resource_policy(self) -> Optional[PolicyDocument]:
        pass
