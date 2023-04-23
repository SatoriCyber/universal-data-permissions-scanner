from dataclasses import dataclass
from typing import Dict, List, Set

from aws_ptrp.iam.policy import PolicyDocumentCtx
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import PathUserGroupNodeBase
from aws_ptrp.ptrp_models import AwsPtrpPathNodeType
from boto3 import Session
from serde import serde


@serde
@dataclass
class IamIdentityCenterGroup(PathUserGroupNodeBase):
    group_name: str
    group_id: str
    group_user_ids: Set[str]

    def get_node_arn(self) -> str:
        return self.group_id

    def get_node_name(self) -> str:
        return self.group_name

    def __eq__(self, other):
        return self.group_id == other.group_id

    def __hash__(self):
        return hash(self.group_id)

    def __repr__(self):
        return self.group_id

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return AwsPtrpPathNodeType.IAM_IDENTITY_CENTER_GROUP

    def get_attached_policies_arn(self) -> List[str]:
        return []

    def get_inline_policies_ctx(self) -> List[PolicyDocumentCtx]:
        return []


def get_iam_identity_center_groups(
    session: Session, identity_store_id: str, region: str
) -> Dict[str, IamIdentityCenterGroup]:
    identity_store_client = session.client("identitystore", region_name=region)
    ret: Dict[str, IamIdentityCenterGroup] = {}

    groups = identity_store_client.list_groups(IdentityStoreId=identity_store_id)['Groups']
    for group in groups:
        group_id: str = group['GroupId']
        group_memberships = identity_store_client.list_group_memberships(
            IdentityStoreId=identity_store_id, GroupId=group_id
        )['GroupMemberships']
        group_user_ids = set([group_membership['MemberId']['UserId'] for group_membership in group_memberships])
        ret[group_id] = IamIdentityCenterGroup(
            group_name=group['DisplayName'],
            group_id=group_id,
            group_user_ids=group_user_ids,
        )

    return ret
