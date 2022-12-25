from dataclasses import dataclass
from serde import serde

from authz_analyzer.datastores.aws.iam.policy.policy_document import PolicyDocument


@serde(rename_all="pascalcase")
@dataclass
class UserPolicy:
    user_name: str
    policy_name: str
    policy_document: PolicyDocument
