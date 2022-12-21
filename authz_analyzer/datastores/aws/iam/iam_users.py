from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type, Union

from boto3 import Session
from serde import deserialize, field, from_dict, serde, serialize

from authz_analyzer.datastores.aws.iam.policy import Policy, PolicyDocument, PolicyDocumentGetterBase, UserPolicy
from authz_analyzer.datastores.aws.iam.policy.principal import PolicyPrincipal
from authz_analyzer.datastores.aws.utils.pagination import paginate_response_list


@serde
@dataclass
class IAMUser(PolicyDocumentGetterBase):
    user_name: str
    user_id: str
    path: str
    user_policies: List[UserPolicy]
    attached_policies_arn: List[str]
    arn: PolicyPrincipal = field(deserializer=PolicyPrincipal.from_iam_user, serializer=PolicyPrincipal.to_iam_user)
    
    def __eq__(self, other):
        return self.user_id == other.user_id

    def __repr__(self):
        return self.arn.to_iam_user()
         
    def __hash__(self):
        return hash(self.user_id)

    @property
    def policy_documents(self) -> List[PolicyDocument]:
        return list(map(lambda x: x.policy_document , self.user_policies))
    
    @property
    def parent_arn(self) -> str:
        return self.arn.principal_str

    
def get_iam_users(session: Session) -> Dict[str, IAMUser]:
    iam_client = session.client('iam')
    ret: Dict[str, IAMUser] = {}

    users = paginate_response_list(iam_client.list_users, 'Users')
    for user in users:
        user_name = user['UserName']
        user_id = user['UserId']
        arn = user['Arn']
        path = user['Path']

        user_policies_response = paginate_response_list(iam_client.list_user_policies, 'PolicyNames', UserName=user_name)
        user_policies: List[UserPolicy] = []
        for user_policy_response in user_policies_response:
            user_policies.append(from_dict(UserPolicy, iam_client.get_user_policy(UserName=user_name, PolicyName=user_policy_response)))

        attached_policies = paginate_response_list(
            iam_client.list_attached_user_policies, 'AttachedPolicies', UserName=user_name, PathPrefix=path
        )
        attached_policies_arn = [attached_policy['PolicyArn'] for attached_policy in attached_policies]
        user_principal_arn = PolicyPrincipal.load_aws(arn)
        ret[user_id] = IAMUser(
            user_name=user_name,
            user_id=user_id,
            arn=user_principal_arn,
            path=path,
            user_policies=user_policies,
            attached_policies_arn=attached_policies_arn,
        )

    return ret
