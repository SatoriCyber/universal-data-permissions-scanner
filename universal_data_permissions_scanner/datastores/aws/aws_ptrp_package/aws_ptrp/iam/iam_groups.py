from dataclasses import dataclass
from typing import Dict, List, Set

from aws_ptrp.iam.policy import GroupPolicy, PolicyDocumentCtx
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import PathUserGroupNodeBase
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpPathNodeType
from aws_ptrp.utils.pagination import paginate_response_list
from boto3 import Session
from serde import from_dict, serde


@serde
@dataclass
class IAMGroup(PathUserGroupNodeBase):
    group_name: str
    group_id: str
    arn: str
    path: str
    group_user_ids: Set[str]
    group_policies: List[GroupPolicy]
    attached_policies_arn: List[str]

    def __eq__(self, other):
        return self.group_id == other.group_id

    def __hash__(self):
        return hash(self.group_id)

    def __repr__(self):
        return self.arn

    def _extract_aws_account_id_from_arn_of_iam_entity(self) -> str:
        return self.arn[self.arn.find(":iam::") + 6 : self.arn.find(":group/")]

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return AwsPtrpPathNodeType.IAM_GROUP

    # NodeBase
    def get_node_name(self) -> str:
        return self.group_name

    def get_node_arn(self) -> str:
        return self.arn

    # impl PoliciesNodeBase
    def get_attached_policies_arn(self) -> List[str]:
        return self.attached_policies_arn

    def get_inline_policies_ctx(self) -> List[PolicyDocumentCtx]:
        aws_account_id = self._extract_aws_account_id_from_arn_of_iam_entity()
        return list(
            map(
                lambda x: PolicyDocumentCtx(
                    policy_document=x.policy_document,
                    parent_arn=self.arn,
                    policy_name=x.policy_name,
                    parent_aws_account_id=aws_account_id,
                ),
                self.group_policies,
            )
        )


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
        group_user_ids = set()
        for group_user in group_users:
            group_user_ids.add(group_user['UserId'])

        group_policies_response = paginate_response_list(
            iam_client.list_group_policies, 'PolicyNames', GroupName=group_name
        )
        group_policies: List[GroupPolicy] = []
        for group_policy_response in group_policies_response:
            group_policies.append(
                from_dict(
                    GroupPolicy, iam_client.get_group_policy(GroupName=group_name, PolicyName=group_policy_response)
                )  # type: ignore
            )

        attached_policies = paginate_response_list(
            iam_client.list_attached_group_policies, 'AttachedPolicies', GroupName=group_name
        )
        attached_policies_arn = [attached_policy['PolicyArn'] for attached_policy in attached_policies]

        ret[arn] = IAMGroup(
            group_name=group_name,
            group_id=group_id,
            arn=arn,
            path=path,
            group_user_ids=group_user_ids,
            group_policies=group_policies,
            attached_policies_arn=attached_policies_arn,
        )

    return ret
