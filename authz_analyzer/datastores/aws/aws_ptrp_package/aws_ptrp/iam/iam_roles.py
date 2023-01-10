from dataclasses import dataclass
from typing import Dict, List, Tuple

from boto3 import Session
from serde import serde, from_dict

from authz_analyzer.models.model import AuthzPathElementType
from aws_ptrp.iam.policy import PolicyDocument
from aws_ptrp.iam.policy.principal import StmtPrincipal
from aws_ptrp.permissions_resolver.identity_to_resource_nodes_base import (
    PathRoleIdentityNodeBase,
)
from aws_ptrp.services.service_resource_base import ServiceResourceBase
from aws_ptrp.iam.role.role_policy import RolePolicy
from aws_ptrp.utils.pagination import paginate_response_list


@dataclass
class IAMRoleSession(PathRoleIdentityNodeBase):
    role: 'IAMRole'
    session_name: str

    def __repr__(self):
        return f"{self.role.__repr__()} + Session: {self.session_name}"

    def __eq__(self, other):
        return self.role.__eq__(other.role) and self.session_name == other.session_name

    def __hash__(self):
        return hash(self.role.__hash__()) + hash(self.session_name)

    # impl PathNodeBase
    def get_path_type(self) -> AuthzPathElementType:
        return AuthzPathElementType.ROLE_SESSION

    def get_path_name(self) -> str:
        return f"{self.role.role_name}/{self.session_name}"

    def get_path_arn(self) -> str:
        return self.role.arn

    # impl IdentityNodeBase
    def get_stmt_principal(self) -> StmtPrincipal:
        return StmtPrincipal.load_from_iam_role_session(self.role.get_role_session_arn(self.session_name))

    # impl IdentityPoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.role.get_attached_policies_arn()

    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        return self.role.get_inline_policies_and_names()


@serde
@dataclass
class IAMRole(PathRoleIdentityNodeBase, ServiceResourceBase):
    role_id: str
    role_name: str
    arn: str
    path: str
    assume_role_policy_document: PolicyDocument
    role_policies: List[RolePolicy]
    attached_policies_arn: List[str]

    def __repr__(self):
        return self.arn

    def __eq__(self, other):
        return self.role_id == other.role_id

    def __hash__(self):
        return hash(self.role_id)

    def get_role_session_arn(self, session_name) -> str:
        role_prefix_arn = self.arn.split(":role/", 1)[0]
        return f"{role_prefix_arn}:assumed-role/{self.role_name}/{session_name}"

    # impl ServiceResourceBase
    def get_resource_arn(self) -> str:
        return self.arn

    def get_resource_name(self) -> str:
        return self.role_name

    # impl PathNodeBase
    def get_path_type(self) -> AuthzPathElementType:
        return AuthzPathElementType.IAM_ROLE

    def get_path_name(self) -> str:
        return self.role_name

    def get_path_arn(self) -> str:
        return self.arn

    # impl IdentityNodeBase
    def get_stmt_principal(self) -> StmtPrincipal:
        return StmtPrincipal.load_from_iam_role(self.arn)

    # impl IdentityPoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.attached_policies_arn

    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        return list(map(lambda x: (x.policy_document, x.policy_name), self.role_policies))


def get_iam_roles(session: Session) -> Dict[str, IAMRole]:
    iam_client = session.client('iam')
    ret: Dict[str, IAMRole] = {}

    roles = paginate_response_list(iam_client.list_roles, 'Roles')
    for role in roles:
        role_name = role['RoleName']
        role_id = role['RoleId']
        arn = role['Arn']
        path = role['Path']
        assume_role_policy_document_response = role['AssumeRolePolicyDocument']
        if assume_role_policy_document_response:
            assume_role_policy_document = from_dict(PolicyDocument, assume_role_policy_document_response)

            role_policies_response = paginate_response_list(
                iam_client.list_role_policies, 'PolicyNames', RoleName=role_name
            )
            role_policies: List[RolePolicy] = []
            for role_policy_response in role_policies_response:
                role_policies.append(
                    from_dict(
                        RolePolicy, iam_client.get_role_policy(RoleName=role_name, PolicyName=role_policy_response)
                    )
                )

            attached_policies = paginate_response_list(
                iam_client.list_attached_role_policies, 'AttachedPolicies', RoleName=role_name, PathPrefix=path
            )
            attached_policies_arn = [attached_policy['PolicyArn'] for attached_policy in attached_policies]

            ret[arn] = IAMRole(
                role_name=role_name,
                role_id=role_id,
                arn=arn,
                path=path,
                assume_role_policy_document=assume_role_policy_document,
                role_policies=role_policies,
                attached_policies_arn=attached_policies_arn,
            )

    return ret
