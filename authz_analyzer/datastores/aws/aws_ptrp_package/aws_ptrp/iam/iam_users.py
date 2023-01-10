from dataclasses import dataclass
from typing import Dict, List, Tuple

from boto3 import Session
from serde import serde, field, from_dict

from aws_ptrp.iam.policy import PolicyDocument, UserPolicy
from aws_ptrp.permissions_resolver.identity_to_resource_line import IdentityNodeBase
from aws_ptrp.iam.policy.principal import StmtPrincipal
from aws_ptrp.utils.pagination import paginate_response_list


@serde
@dataclass
class IAMUser(IdentityNodeBase):
    user_name: str
    user_id: str
    path: str
    user_policies: List[UserPolicy]
    attached_policies_arn: List[str]
    identity_principal: StmtPrincipal = field(
        deserializer=StmtPrincipal.from_policy_principal_str,
        serializer=StmtPrincipal.to_policy_principal_str,
    )

    def __eq__(self, other):
        return self.user_id == other.user_id

    def __repr__(self):
        return self.identity_principal.get_arn()

    def __hash__(self):
        return hash(self.user_id)

    # impl IdentityNodeBase
    def get_stmt_principal(self) -> StmtPrincipal:
        return self.identity_principal

    # IdentityPoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.attached_policies_arn

    def get_inline_policies_and_names(self) -> List[Tuple[PolicyDocument, str]]:
        return list(map(lambda x: (x.policy_document, x.policy_name), self.user_policies))


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
                from_dict(UserPolicy, iam_client.get_user_policy(UserName=user_name, PolicyName=user_policy_response))
            )

        attached_policies = paginate_response_list(
            iam_client.list_attached_user_policies, 'AttachedPolicies', UserName=user_name, PathPrefix=path
        )
        attached_policies_arn = [attached_policy['PolicyArn'] for attached_policy in attached_policies]
        user_principal_arn = StmtPrincipal.load_from_iam_user(arn)
        ret[arn] = IAMUser(
            user_name=user_name,
            user_id=user_id,
            identity_principal=user_principal_arn,
            path=path,
            user_policies=user_policies,
            attached_policies_arn=attached_policies_arn,
        )

    return ret
