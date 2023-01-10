from dataclasses import dataclass
from typing import Dict

from boto3 import Session
from serde import serde, from_dict

from aws_ptrp.iam.policy import Policy, PolicyDocument
from aws_ptrp.utils.pagination import paginate_response_list


@serde
@dataclass
class IAMPolicy:
    policy: Policy
    policy_document: PolicyDocument

    def __eq__(self, other):
        return self.policy.policy_id == other.policy.policy_id

    def __hash__(self):
        return hash(self.policy.policy_id)

    def __repr__(self):
        return self.policy.arn


def get_iam_policies(session: Session) -> Dict[str, IAMPolicy]:
    iam_client = session.client('iam')
    ret: Dict[str, IAMPolicy] = {}

    list_policies = paginate_response_list(iam_client.list_policies, 'Policies', OnlyAttached=True)
    for list_policy_response in list_policies:
        # Due to the comment in the aws API for list_policies we are using the get_policy for each policy
        # "IAM resource-listing operations return a subset of the available attributes for the resource. For example, this operation does not return tags, even though they are an attribute of the returned object. To view all of the information for a customer manged policy, see GetPolicy."
        arn = list_policy_response['Arn']
        policy_response = iam_client.get_policy(PolicyArn=arn)['Policy']
        policy = from_dict(Policy, policy_response)

        policy_version_response = iam_client.get_policy_version(PolicyArn=arn, VersionId=policy.default_version_id)
        policy_version_response = policy_version_response['PolicyVersion']['Document']
        policy_document = from_dict(PolicyDocument, policy_version_response)

        ret[policy.arn] = IAMPolicy(
            policy=policy,
            policy_document=policy_document,
        )
    return ret
