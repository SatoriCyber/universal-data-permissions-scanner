from dataclasses import dataclass
from typing import Dict, List, Tuple

from boto3 import Session
from serde import serde, from_dict

from aws_ptrp.iam.policy import PolicyDocument
from aws_ptrp.principals import Principal
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import (
    PathRoleNodeBase,
)
from aws_ptrp.services.service_resource_base import ServiceResourceBase
from aws_ptrp.iam.role.role_policy import RolePolicy
from aws_ptrp.utils.pagination import paginate_response_list

from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpPathNodeType


@dataclass
class IAMRoleSession(PathRoleNodeBase):
    role: 'IAMRole'
    role_session_principal: Principal

    def __repr__(self):
        return self.get_path_arn()

    def __eq__(self, other):
        return self.get_path_arn() == other.get_path_arn()

    def __hash__(self):
        return hash(self.get_path_arn())

    # impl PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return AwsPtrpPathNodeType.ROLE_SESSION

    def get_path_name(self) -> str:
        return self.get_stmt_principal().get_name()

    def get_path_arn(self) -> str:
        return self.get_stmt_principal().get_arn()

    # impl PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return self.role_session_principal

    # impl PrincipalPoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.role.get_attached_policies_arn()

    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        return self.role.get_inline_policies_and_names()


@serde
@dataclass
class IAMRole(PathRoleNodeBase, ServiceResourceBase):
    role_id: str
    role_name: str
    aws_account_id: str
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

    # impl ServiceResourceBase
    def get_resource_arn(self) -> str:
        return self.arn

    def get_resource_name(self) -> str:
        return self.role_name

    def get_resource_account_id(self) -> str:
        return self.aws_account_id

    # impl PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return AwsPtrpPathNodeType.IAM_ROLE

    def get_path_name(self) -> str:
        return self.role_name

    def get_path_arn(self) -> str:
        return self.arn

    # impl PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return Principal.load_from_iam_role(self.arn)

    # impl PrincipalPoliciesNodeBase
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
        arn: str = role['Arn']
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
                iam_client.list_attached_role_policies, 'AttachedPolicies', RoleName=role_name
            )

            attached_policies_arn = [attached_policy['PolicyArn'] for attached_policy in attached_policies]
            aws_account_id_start_index = arn.find(":iam::")
            aws_account_id_end_index = arn.find(":role/")
            aws_account_id = arn[aws_account_id_start_index + 6 : aws_account_id_end_index]
            ret[arn] = IAMRole(
                role_name=role_name,
                aws_account_id=aws_account_id,
                role_id=role_id,
                arn=arn,
                path=path,
                assume_role_policy_document=assume_role_policy_document,
                role_policies=role_policies,
                attached_policies_arn=attached_policies_arn,
            )

    return ret
