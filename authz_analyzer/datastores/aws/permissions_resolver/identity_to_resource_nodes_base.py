from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Tuple, Optional

from authz_analyzer.datastores.aws.services import ServiceResourceBase
from authz_analyzer.datastores.aws.iam.policy.principal import StmtPrincipal
from authz_analyzer.datastores.aws.iam.policy.policy_document import PolicyDocument
from authz_analyzer.models.model import AuthzPathElementType, AuthzPathElement, AssetType


class IdentityPoliciesNodeBase(ABC):
    @abstractmethod
    def get_attached_policies_arn(self) -> List[str]:
        pass

    @abstractmethod
    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        pass


class IdentityNodeBase(IdentityPoliciesNodeBase):
    @abstractmethod
    def get_stmt_principal(self) -> StmtPrincipal:
        pass

    # def get_permission_boundary(self) -> Optional[PolicyDocument]:
    #     return None

    # def get_session_policies(self) -> List[PolicyDocument]:
    #     return []


class PathNodeBase(ABC):
    @abstractmethod
    def get_path_type(self) -> AuthzPathElementType:
        pass

    @abstractmethod
    def get_path_name(self) -> str:
        pass

    @abstractmethod
    def get_path_arn(self) -> str:
        pass


class PathRoleIdentityNodeBase(IdentityNodeBase, PathNodeBase):
    pass


class PathIdentityPoliciesNodeBase(IdentityPoliciesNodeBase, PathNodeBase):
    pass


@dataclass
class PathIdentityPoliciesNode:
    path_identity_policies_base: PathIdentityPoliciesNodeBase
    note: str

    def get_authz_path_element(self) -> AuthzPathElement:
        return AuthzPathElement(
            id=self.path_identity_policies_base.get_path_arn(),
            name=self.path_identity_policies_base.get_path_name(),
            type=self.path_identity_policies_base.get_path_type(),
            note=self.note,
        )

    def __repr__(self):
        return f"PathIdentityPoliciesNode({self.path_identity_policies_base.__repr__()})"

    def __eq__(self, other):
        return self.path_identity_policies_base.__eq__(other.path_identity_policies_base)

    def __hash__(self):
        return self.path_identity_policies_base.__hash__()


@dataclass
class PathRoleIdentityNode:
    path_role_identity_base: PathRoleIdentityNodeBase
    note: str

    def get_authz_path_element(self) -> AuthzPathElement:
        return AuthzPathElement(
            id=self.path_role_identity_base.get_path_arn(),
            name=self.path_role_identity_base.get_path_name(),
            type=self.path_role_identity_base.get_path_type(),
            note=self.note,
        )

    def __repr__(self):
        return f"PathRoleIdentityNode({self.path_role_identity_base.__repr__()})"

    def __eq__(self, other):
        return self.path_role_identity_base.__eq__(other.path_role_identity_base)

    def __hash__(self):
        return self.path_role_identity_base.__hash__()


@dataclass
class TargetPolicyNode:
    path_element_type: AuthzPathElementType
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

    def get_authz_path_element(self) -> AuthzPathElement:
        return AuthzPathElement(
            id=self.path_arn,
            name=self.path_name,
            type=self.path_element_type,
            note=self.note,
        )


class ResourceNodeBase(ServiceResourceBase):
    @abstractmethod
    def get_asset_type(self) -> AssetType:
        pass

    @abstractmethod
    def get_resource_policy(self) -> Optional[PolicyDocument]:
        pass
