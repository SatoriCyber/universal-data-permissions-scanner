from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from aws_ptrp.iam.policy import PolicyDocument, PolicyDocumentCtx
from aws_ptrp.iam.role.role_policy import RolePolicy
from aws_ptrp.principals import Principal
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import PathRoleNodeBase
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpPathNodeType
from aws_ptrp.services.service_resource_base import ServiceResourceBase
from aws_ptrp.utils.pagination import paginate_response_list
from boto3 import Session
from serde import field, from_dict, serde


@dataclass
class RoleSession(PathRoleNodeBase):
    iam_role: PathRoleNodeBase
    role_session_principal: Principal

    def __repr__(self):
        return self.get_node_arn()

    def __eq__(self, other):
        return self.get_node_arn() == other.get_node_arn()

    def __hash__(self):
        return hash(self.get_node_arn())

    # NodeBase
    def get_node_arn(self) -> str:
        return self.get_stmt_principal().get_arn()

    def get_node_name(self) -> str:
        return self.get_stmt_principal().get_name()

    # impl PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return AwsPtrpPathNodeType.ROLE_SESSION

    # impl PathRoleNodeBase
    def get_service_resource(self) -> ServiceResourceBase:
        assert isinstance(self.iam_role, ServiceResourceBase)
        return self.iam_role

    # impl PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return self.role_session_principal

    # impl PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.iam_role.get_attached_policies_arn()

    def get_inline_policies_ctx(self) -> List[PolicyDocumentCtx]:
        return self.iam_role.get_inline_policies_ctx()


@serde
@dataclass
class IAMRole(PathRoleNodeBase, ServiceResourceBase):
    role_id: str
    role_name: str
    arn: str
    path: str
    assume_role_policy_document: PolicyDocument
    role_policies: List[RolePolicy]
    attached_policies_arn: List[str]
    _role_sessions: Set[RoleSession] = field(skip=True, default_factory=set)

    def __repr__(self):
        return self.arn

    def __eq__(self, other):
        return self.role_id == other.role_id

    def __hash__(self):
        return hash(self.role_id)

    def get_role_sessions(self) -> Set[RoleSession]:
        return self._role_sessions

    def add_role_session(self, role_session: RoleSession):
        self._role_sessions.add(role_session)

    def _extract_aws_account_id_from_arn_of_iam_entity(self) -> str:
        return self.arn[self.arn.find(":iam::") + 6 : self.arn.find(":role/")]

    # impl ServiceResourceBase
    def get_resource_arn(self) -> str:
        return self.arn

    def get_resource_name(self) -> str:
        return self.role_name

    def get_resource_policy(self) -> Optional[PolicyDocument]:
        return self.assume_role_policy_document

    def get_resource_account_id(self) -> str:
        return self._extract_aws_account_id_from_arn_of_iam_entity()

    # # impl PrincipalAndPoliciesNodeBase
    # def get_permission_boundary(self) -> Optional[PolicyDocument]:
    #     return None

    # def get_session_policies(self) -> List[PolicyDocument]:
    #     return []

    # NodeBase
    def get_node_arn(self) -> str:
        return self.arn

    def get_node_name(self) -> str:
        return self.role_name

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return AwsPtrpPathNodeType.IAM_ROLE

    # impl PathRoleNodeBase
    def get_service_resource(self) -> ServiceResourceBase:
        return self

    # impl PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return Principal.load_from_iam_role(self.arn)

    # impl PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.attached_policies_arn

    def get_inline_policies_ctx(self) -> List[PolicyDocumentCtx]:
        aws_account_id = self._extract_aws_account_id_from_arn_of_iam_entity()
        return list(
            map(
                lambda x: PolicyDocumentCtx(
                    policy_document=x.policy_document,
                    parent_arn=self.arn,
                    policy_name=x.policy_name,
                    parent_aws_account_id=aws_account_id,
                ),
                self.role_policies,
            )
        )


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
            assume_role_policy_document: PolicyDocument = from_dict(
                PolicyDocument, assume_role_policy_document_response
            )  # type: ignore

            role_policies_response = paginate_response_list(
                iam_client.list_role_policies, 'PolicyNames', RoleName=role_name
            )
            role_policies: List[RolePolicy] = []
            for role_policy_response in role_policies_response:
                role_policies.append(
                    from_dict(
                        RolePolicy, iam_client.get_role_policy(RoleName=role_name, PolicyName=role_policy_response)
                    )  # type: ignore
                )

            attached_policies = paginate_response_list(
                iam_client.list_attached_role_policies, 'AttachedPolicies', RoleName=role_name
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
