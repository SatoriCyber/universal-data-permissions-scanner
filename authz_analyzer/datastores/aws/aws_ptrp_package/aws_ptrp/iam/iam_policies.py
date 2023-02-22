from dataclasses import dataclass
from typing import Dict

from aws_ptrp.iam.policy import Policy
from aws_ptrp.iam.policy.policy_document import PolicyDocument, PolicyDocumentCtx
from aws_ptrp.utils.pagination import paginate_response_list
from boto3 import Session
from serde import from_dict, serde


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

    @staticmethod
    def extract_aws_account_id_from_arn_of_iam_entity(arn: str) -> str:
        return arn[arn.find(":iam::") + 6 : arn.find(":policy/")]

    def to_policy_document_ctx(self) -> PolicyDocumentCtx:
        aws_account_id = IAMPolicy.extract_aws_account_id_from_arn_of_iam_entity(self.policy.arn)
        return PolicyDocumentCtx(
            policy_document=self.policy_document,
            policy_name=self.policy.policy_name,
            parent_arn=self.policy.arn,
            parent_aws_account_id=aws_account_id,
        )


def get_iam_policies(session: Session) -> Dict[str, IAMPolicy]:
    iam_client = session.client('iam')
    ret: Dict[str, IAMPolicy] = {}

    list_policies = paginate_response_list(iam_client.list_policies, 'Policies', OnlyAttached=True)
    for list_policy_response in list_policies:
        # Due to the comment in the aws API for list_policies we are using the get_policy for each policy
        # "IAM resource-listing operations return a subset of the available attributes for the resource. For example, this operation does not return tags, even though they are an attribute of the returned object. To view all of the information for a customer manged policy, see GetPolicy."
        arn = list_policy_response['Arn']
        policy_response = iam_client.get_policy(PolicyArn=arn)['Policy']
        policy: Policy = from_dict(Policy, policy_response)  # type: ignore

        policy_version_response = iam_client.get_policy_version(PolicyArn=arn, VersionId=policy.default_version_id)
        policy_version_response = policy_version_response['PolicyVersion']['Document']
        policy_document: PolicyDocument = from_dict(PolicyDocument, policy_version_response)  # type: ignore
        ret[policy.arn] = IAMPolicy(
            policy=policy,
            policy_document=policy_document,
        )
    return ret
