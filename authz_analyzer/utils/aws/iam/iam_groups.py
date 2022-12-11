from boto3 import Session
from typing import Dict, Any, Optional, Type, List, Union
from dataclasses import dataclass
from authz_analyzer.utils.aws.pagination import paginate_response_list
from authz_analyzer.utils.aws.iam.policy import GroupPolicy, Policy, PolicyDocument


@dataclass
class IAMGroup:
    group_name: str
    group_id: str
    arn: str
    path: str
    group_user_ids: List[str]
    group_policies: List[GroupPolicy]
    attached_policies_arn: List[str]


def get_iam_groups(session: Session) -> Dict[str, IAMGroup]:
    iam_client = session.client('iam')
    ret: Dict[str, IAMGroup] = {}

    groups = paginate_response_list(iam_client.list_groups, 'Groups')
    for group in groups:
        group_name = group['GroupName']
        group_id = group['GroupId']
        arn = group['Arn']
        path = group['Path']

        group_users = paginate_response_list(iam_client.get_group, 'Users', GroupName=group_name)
        group_user_ids = [group_user['UserId'] for group_user in group_users]
        
        group_policies_response = paginate_response_list(iam_client.list_group_policies, 'PolicyNames', GroupName=group_name)
        group_policies: List[GroupPolicy] = []
        for group_policy_response in group_policies_response:
            group_policies.append(GroupPolicy(**iam_client.get_group_policy(GroupName=group_name, PolicyName=group_policy_response)))

        attached_policies = paginate_response_list(
            iam_client.list_attached_group_policies, 'AttachedPolicies', GroupName=group_name, PathPrefix=path
        )
        attached_policies_arn = [attached_policy['PolicyArn'] for attached_policy in attached_policies]
        
        ret[group_id] = IAMGroup(
            group_name=group_name,
            group_id=group_id,
            arn=arn,
            path=path,
            group_user_ids=group_user_ids,
            group_policies=group_policies,
            attached_policies_arn=attached_policies_arn)

    return ret
