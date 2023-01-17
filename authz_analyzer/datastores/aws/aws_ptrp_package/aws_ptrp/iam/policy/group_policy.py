from dataclasses import dataclass

from aws_ptrp.iam.policy.policy_document import PolicyDocument
from serde import serde


@serde(rename_all="pascalcase")
@dataclass
class GroupPolicy:
    group_name: str
    policy_name: str
    policy_document: PolicyDocument
