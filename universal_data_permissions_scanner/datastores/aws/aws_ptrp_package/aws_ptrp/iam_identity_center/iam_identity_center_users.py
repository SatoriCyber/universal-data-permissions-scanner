from dataclasses import dataclass
from typing import Dict, List

from aws_ptrp.iam.policy import PolicyDocumentCtx
from aws_ptrp.principals.principal import Principal
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import PrincipalAndPoliciesNodeBase
from aws_ptrp.ptrp_models import AwsPrincipalType
from boto3 import Session
from serde import serde


@serde
@dataclass
class IamIdentityCenterUser(PrincipalAndPoliciesNodeBase):
    user_name: str
    user_id: str

    def get_node_arn(self) -> str:
        return self.user_id

    def get_node_name(self) -> str:
        return self.user_name

    def __eq__(self, other):
        return self.user_id == other.user_id

    def __hash__(self):
        return hash(self.user_id)

    def __repr__(self):
        return self.user_id

    # PrincipalNodeBase
    def get_stmt_principal(self) -> Principal:
        return Principal(
            principal_type=AwsPrincipalType.IAM_IDENTITY_CENTER_USER,
            policy_principal_str=self.user_id,
            name=self.user_name,
            principal_metadata=None,
        )

    # PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return []

    def get_inline_policies_ctx(self) -> List[PolicyDocumentCtx]:
        return []


def get_iam_identity_center_users(
    session: Session, identity_store_id: str, region: str
) -> Dict[str, 'IamIdentityCenterUser']:
    identity_store_client = session.client("identitystore", region_name=region)
    ret: Dict[str, IamIdentityCenterUser] = {}

    users = identity_store_client.list_users(IdentityStoreId=identity_store_id)['Users']
    for user in users:
        user_id: str = user['UserId']
        ret[user_id] = IamIdentityCenterUser(
            user_name=user['UserName'],
            user_id=user_id,
        )

    return ret
