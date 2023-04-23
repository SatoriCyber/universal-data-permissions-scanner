from dataclasses import dataclass
from logging import Logger
from typing import Dict, Generator, List, Optional, Set

from aws_ptrp.iam.iam_entities import IAMAccountEntities
from aws_ptrp.iam_identity_center.iam_identity_center_groups import (
    IamIdentityCenterGroup,
    get_iam_identity_center_groups,
)
from aws_ptrp.iam_identity_center.iam_identity_center_users import IamIdentityCenterUser, get_iam_identity_center_users
from aws_ptrp.iam_identity_center.permission_sets import PermissionsSet, get_permission_sets
from aws_ptrp.utils.assume_role import AwsAssumeRole
from aws_ptrp.utils.create_session import create_session_with_assume_role
from boto3 import Session
from serde import serde


@serde
@dataclass
class IamIdentityCenterEntities:
    instance_arn: str
    identity_store_id: str
    account_id: str
    region: str
    identity_center_users: Dict[str, IamIdentityCenterUser]  # key is user id
    identity_center_groups: Dict[str, IamIdentityCenterGroup]  # key is group id
    permission_sets: Dict[str, PermissionsSet]  # key is permission set arn

    @classmethod
    def load_from_session(
        cls,
        logger: Logger,
        session: Session,
        instance_arn: str,
        identity_store_id: str,
        account_id: str,
        region: str,
    ) -> 'IamIdentityCenterEntities':
        identity_center_users: Dict[str, IamIdentityCenterUser] = get_iam_identity_center_users(
            session, identity_store_id, region
        )
        logger.info(f"Got identity_center_users: {identity_center_users.values()}")

        identity_center_groups: Dict[str, IamIdentityCenterGroup] = get_iam_identity_center_groups(
            session, identity_store_id, region
        )
        logger.info(f"Got identity_center_groups: {identity_center_groups.values()}")

        permission_sets: Dict[str, PermissionsSet] = get_permission_sets(session, instance_arn, region)
        logger.info(f"Got permission_sets: {permission_sets.values()}")

        return cls(
            instance_arn=instance_arn,
            identity_store_id=identity_store_id,
            account_id=account_id,
            region=region,
            identity_center_users=identity_center_users,
            identity_center_groups=identity_center_groups,
            permission_sets=permission_sets,
        )

    def yield_permission_sets(self) -> Generator[PermissionsSet, None, None]:
        for permission_set in self.permission_sets.values():
            yield permission_set

    def yield_identity_center_users(self) -> Generator[IamIdentityCenterUser, None, None]:
        for user in self.identity_center_users.values():
            yield user

    def yield_identity_center_groups(self) -> Generator[IamIdentityCenterGroup, None, None]:
        for group in self.identity_center_groups.values():
            yield group

    def yield_identity_center_groups_for_user(self, user_id: str) -> Generator[IamIdentityCenterGroup, None, None]:
        for group in self.identity_center_groups.values():
            if user_id in group.group_user_ids:
                yield group

    def generate_reserved_sso_arn_prefix(self, account_id: str, permission_set_name: str) -> str:
        return f"arn:aws:iam::{account_id}:role/aws-reserved/sso.amazonaws.com/{self.region}/AWSReservedSSO_{permission_set_name}_"


def find_and_scan_iam_identity_center_instance(
    logger: Logger,
    iam_entities_for_accounts: Dict[str, IAMAccountEntities],
    accounts: List[AwsAssumeRole],
) -> Optional[IamIdentityCenterEntities]:
    sso_roles_regions: Dict[str, Set[str]] = {}
    for account_id, iam_entities in iam_entities_for_accounts.items():
        sso_roles_regions[account_id] = iam_entities.get_available_regions_for_reserved_sso_roles_in_account()

    for account in accounts:
        account_id = account.get_account_id()
        if account_id in sso_roles_regions:
            session: Session = create_session_with_assume_role(account.role_arn, account.external_id)
            for region in sso_roles_regions[account_id]:
                try:
                    logger.info(
                        "Trying to find identity center instance in region %s for account %s", region, account_id
                    )
                    client = session.client("sso-admin", region_name=region)
                    response = client.list_instances()
                    # Currently we support only one idc instance
                    if response["Instances"]:
                        instance = response["Instances"][0]
                        instance_arn = instance["InstanceArn"]
                        identity_store_id = instance["IdentityStoreId"]
                        try:
                            return IamIdentityCenterEntities.load_from_session(
                                logger,
                                session,
                                instance_arn,
                                identity_store_id,
                                account_id,
                                region,
                            )
                        except Exception as err:  # pylint: disable=broad-exception-caught
                            logger.warning(
                                "Failed to scan identity center instance %s: %s",
                                instance_arn,
                                err,
                            )
                            return None
                except Exception as err:  # pylint: disable=broad-exception-caught
                    logger.warning("Failed to find identity center instance in region %s: %s", region, err)
    return None
