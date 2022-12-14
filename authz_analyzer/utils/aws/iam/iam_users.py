from boto3 import Session
from typing import Dict, Any, Optional, Type, List, Union
from dataclasses import dataclass
from pydantic import BaseModel
from authz_analyzer.utils.aws.pagination import paginate_response_list
from authz_analyzer.utils.aws.iam.policy import UserPolicy, Policy, PolicyDocument


class IAMUser(BaseModel):
    user_name: str
    user_id: str
    arn: str
    path: str
    user_policies: List[UserPolicy]
    attached_policies_arn: List[str]
    
    def __eq__(self, other):
        return self.user_id == other.user_id

    def __repr__(self):
        return self.arn
         
    def __hash__(self):
        return hash(self.user_id)


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
            user_policies.append(UserPolicy(**iam_client.get_user_policy(UserName=user_name, PolicyName=user_policy_response)))

        attached_policies = paginate_response_list(
            iam_client.list_attached_user_policies, 'AttachedPolicies', UserName=user_name, PathPrefix=path
        )
        attached_policies_arn = [attached_policy['PolicyArn'] for attached_policy in attached_policies]

        ret[user_id] = IAMUser(
            user_name=user_name,
            user_id=user_id,
            arn=arn,
            path=path,
            user_policies=user_policies,
            attached_policies_arn=attached_policies_arn,
        )

    return ret
