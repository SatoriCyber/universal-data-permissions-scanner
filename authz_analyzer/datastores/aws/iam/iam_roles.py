from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type, Union

from boto3 import Session
from serde import deserialize, from_dict, serde, serialize

from authz_analyzer.datastores.aws.iam.policy import PolicyDocument
from authz_analyzer.datastores.aws.iam.role.role_policy import RolePolicy
from authz_analyzer.datastores.aws.utils.pagination import paginate_response_list


@serde
@dataclass

class IAMRole:
    role_id: str
    role_name: str
    arn: str
    path: str
    assume_role_policy_document: PolicyDocument
    role_policies: List[RolePolicy]
    attached_policies_arn: List[str]

    def __eq__(self, other):
        return self.role_id == other.role_id
    
    def __hash__(self):
        return hash(self.role_id)

    def __repr__(self):
        return self.arn
    

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
            
            role_policies_response = paginate_response_list(iam_client.list_role_policies, 'PolicyNames', RoleName=role_name)
            role_policies: List[RolePolicy] = []
            for role_policy_response in role_policies_response:
                role_policies.append(from_dict(RolePolicy, iam_client.get_role_policy(RoleName=role_name, PolicyName=role_policy_response)))

            attached_policies = paginate_response_list(
                iam_client.list_attached_role_policies, 'AttachedPolicies', RoleName=role_name, PathPrefix=path
            )
            attached_policies_arn = [attached_policy['PolicyArn'] for attached_policy in attached_policies]

            ret[role_id] = IAMRole(
                role_name=role_name,
                role_id=role_id,
                arn=arn,
                path=path,
                assume_role_policy_document=assume_role_policy_document,
                role_policies=role_policies,
                attached_policies_arn=attached_policies_arn,
            )

    return ret
