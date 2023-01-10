from dataclasses import dataclass
from serde import serde

from aws_ptrp.iam.policy.policy_document import PolicyDocument


@serde(rename_all="pascalcase")
@dataclass
class RolePolicy:
    role_name: str
    policy_name: str
    policy_document: PolicyDocument
