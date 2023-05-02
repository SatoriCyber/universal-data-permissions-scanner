from dataclasses import dataclass
from typing import Dict, List, Set

from aws_ptrp.iam.policy import PolicyDocumentCtx, UserPolicy
from aws_ptrp.principals import Principal
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import PrincipalAndPoliciesNodeBase
from aws_ptrp.services.federated_user.federated_user_resources import FederatedUserPrincipal
from aws_ptrp.utils.pagination import paginate_response_list
from boto3 import Session
from serde import field, from_dict, serde


@serde
@dataclass
class IAMUser(PrincipalAndPoliciesNodeBase):
    user_name: str
    user_id: str
    path: str
    user_policies: List[UserPolicy]
    attached_policies_arn: List[str]
    arn: str
    _federated_user_principals: Set[FederatedUserPrincipal] = field(skip=True, default_factory=set)

    def __eq__(self, other):
        return self.user_id == other.user_id

    def __repr__(self):
        return self.arn

    def __hash__(self):
        return hash(self.user_id)

    def get_federated_user_principals(self) -> Set[FederatedUserPrincipal]:
        return self._federated_user_principals

    def add_federated_user_principal(self, federated_user_principal: FederatedUserPrincipal):
        self._federated_user_principals.add(federated_user_principal)

    @staticmethod
    def _extract_aws_account_id_from_arn_of_iam_entity(arn: str) -> str:
        return arn[arn.find(":iam::") + 6 : arn.find(":user/")]

    def get_account_id(self) -> str:
        return IAMUser._extract_aws_account_id_from_arn_of_iam_entity(self.arn)

    # # impl PrincipalAndPoliciesNodeBase
    # def get_permission_boundary(self) -> Optional[PolicyDocument]:
    #     return None

    # def get_session_policies(self) -> List[PolicyDocument]:
    #     return []

    # NodeBase
    def get_node_arn(self) -> str:
        return self.arn

    def get_node_name(self) -> str:
        return self.user_name

    # impl PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return Principal.load_from_iam_user(self.arn)

    # PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.attached_policies_arn

    def get_inline_policies_ctx(self) -> List[PolicyDocumentCtx]:
        aws_account_id = IAMUser._extract_aws_account_id_from_arn_of_iam_entity(self.arn)
        return list(
            map(
                lambda x: PolicyDocumentCtx(
                    policy_document=x.policy_document,
                    parent_arn=self.arn,
                    policy_name=x.policy_name,
                    parent_aws_account_id=aws_account_id,
                ),
                self.user_policies,
            )
        )


def get_iam_users(session: Session) -> Dict[str, IAMUser]:
    iam_client = session.client('iam')
    ret: Dict[str, IAMUser] = {}

    users = paginate_response_list(iam_client.list_users, 'Users')
    for user in users:
        user_name = user['UserName']
        user_id = user['UserId']
        arn = user['Arn']
        path = user['Path']

        user_policies_response = paginate_response_list(
            iam_client.list_user_policies, 'PolicyNames', UserName=user_name
        )
        user_policies: List[UserPolicy] = []
        for user_policy_response in user_policies_response:
            user_policies.append(
                from_dict(UserPolicy, iam_client.get_user_policy(UserName=user_name, PolicyName=user_policy_response))  # type: ignore
            )

        attached_policies = paginate_response_list(
            iam_client.list_attached_user_policies, 'AttachedPolicies', UserName=user_name
        )
        attached_policies_arn = [attached_policy['PolicyArn'] for attached_policy in attached_policies]
        ret[arn] = IAMUser(
            user_name=user_name,
            user_id=user_id,
            arn=arn,
            path=path,
            user_policies=user_policies,
            attached_policies_arn=attached_policies_arn,
        )

    return ret
