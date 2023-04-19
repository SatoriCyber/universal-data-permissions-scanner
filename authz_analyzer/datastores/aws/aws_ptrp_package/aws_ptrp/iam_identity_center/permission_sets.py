from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import PathPermissionSetNodeBase
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpPathNodeType
from boto3 import Session
from serde import field, serde


@serde
@dataclass
class PermissionsSet(PathPermissionSetNodeBase):
    name: str
    arn: str
    accounts_assignments: Dict[str, Set[str]] = field(default_factory=list)  # account_id -> set of users and groups ids

    # PathNodeBase
    def get_path_type(self) -> AwsPtrpPathNodeType:
        return AwsPtrpPathNodeType.PERMISSION_SET

    # NodeBase
    def get_node_name(self) -> str:
        return self.name

    def get_node_arn(self) -> str:
        return self.arn

    def get_account_assignments(self, account_id: str) -> Optional[Set[str]]:
        return self.accounts_assignments[account_id] if account_id in self.accounts_assignments else None

    def __eq__(self, other):
        return self.arn == other.arn

    def __hash__(self):
        return hash(self.arn)

    def __repr__(self):
        return self.name


def get_permission_sets(session: Session, instance_arn: str, region: str) -> Dict[str, PermissionsSet]:
    ret: Dict[str, PermissionsSet] = {}
    sso_admin_client = session.client("sso-admin", region_name=region)
    permission_sets = sso_admin_client.list_permission_sets(InstanceArn=instance_arn)['PermissionSets']
    for permission_set_arn in permission_sets:
        name = sso_admin_client.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=permission_set_arn)[
            'PermissionSet'
        ]['Name']

        accounts_assignments: Dict[str, Set[str]] = {}
        provisioned_accounts: List[str] = sso_admin_client.list_accounts_for_provisioned_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
        )['AccountIds']
        for account_id in provisioned_accounts:
            assignments = sso_admin_client.list_account_assignments(
                InstanceArn=instance_arn,
                AccountId=account_id,
                PermissionSetArn=permission_set_arn,
            )['AccountAssignments']
            accounts_assignments[account_id] = set([principal['PrincipalId'] for principal in assignments])

        ret[permission_set_arn] = PermissionsSet(
            name=name,
            arn=permission_set_arn,
            accounts_assignments=accounts_assignments,
        )

    return ret
