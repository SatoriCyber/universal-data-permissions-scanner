import json
from dataclasses import dataclass, field
from logging import Logger
from pathlib import Path
from typing import Dict, Generator, List, Optional, Set

from aws_ptrp.iam.iam_groups import IAMGroup, get_iam_groups
from aws_ptrp.iam.iam_policies import IAMPolicy, get_iam_policies
from aws_ptrp.iam.iam_roles import IAMRole, get_iam_roles
from aws_ptrp.iam.iam_users import IAMUser, get_iam_users
from boto3 import Session
from serde import from_dict, serde


@serde
@dataclass
class IAMAccountEntities:
    iam_users: Dict[str, IAMUser] = field(default_factory=dict)  # key is user arn
    iam_groups: Dict[str, IAMGroup] = field(default_factory=dict)  # key is group arn
    iam_roles: Dict[str, IAMRole] = field(default_factory=dict)  # key is role arn
    iam_policies: Dict[str, IAMPolicy] = field(default_factory=dict)  # key is policy arn

    @classmethod
    def load_from_json_file(cls, _logger: Logger, file_path: Path) -> 'IAMAccountEntities':
        with open(file_path, "r", encoding="utf-8") as file:
            analyzed_ctx_json = json.load(file)
            analyzed_ctx_loaded: 'IAMAccountEntities' = from_dict(IAMAccountEntities, analyzed_ctx_json)  # type: ignore
            return analyzed_ctx_loaded

    def get_attached_iam_groups_for_iam_user(self, iam_user: IAMUser) -> List[IAMGroup]:
        ret: List[IAMGroup] = []
        for iam_group in self.iam_groups.values():
            if iam_user.user_id in iam_group.group_user_ids:
                ret.append(iam_group)
        return ret

    @staticmethod
    def is_valid_aws_account_id(account_id: str) -> bool:
        return account_id.isnumeric()  # assuming all aws account is is numeric

    def pop_iam_managed_policies(self) -> Dict[str, IAMPolicy]:
        keys_to_remove: List[str] = []
        for arn in self.iam_policies:
            account_id: str = IAMPolicy.extract_aws_account_id_from_arn_of_iam_entity(arn)
            if not IAMAccountEntities.is_valid_aws_account_id(account_id):
                keys_to_remove.append(arn)
        return {key: self.iam_policies.pop(key) for key in keys_to_remove}

    @classmethod
    def load_for_account(cls, logger: Logger, account_id: str, session: Session) -> 'IAMAccountEntities':
        logger.info(f"Start pulling IAM entities from aws account: {account_id}...")
        # Get the iam users
        iam_users = get_iam_users(session)
        logger.info(f"Got iam_users: {iam_users.values()}")

        # Get the iam groups
        iam_groups = get_iam_groups(session)
        logger.info(f"Got iam_groups: {iam_groups.values()}")

        # Get the iam roles
        iam_roles = get_iam_roles(session)
        logger.info(f"Got iam_roles: {iam_roles.values()}")

        # Get the iam policies
        iam_policies = get_iam_policies(session)
        logger.info(f"Got iam_policies: {iam_policies.values()}")

        return cls(
            iam_users=iam_users,
            iam_groups=iam_groups,
            iam_roles=iam_roles,
            iam_policies=iam_policies,
        )

    def get_role_with_arn_prefix(self, arn_prefix: str) -> Optional[IAMRole]:
        for role in self.iam_roles.values():
            if role.arn.startswith(arn_prefix):
                return role

        return None

    def get_available_regions_for_reserved_sso_roles_in_account(self) -> Set[str]:
        available_regions_for_account: Set[str] = set()
        for role in self.iam_roles.values():
            if role.get_stmt_principal().is_principal_aws_sso_reserved_role():
                region = role.get_node_arn().split("/")[-2]
                available_regions_for_account.add(region)

        return available_regions_for_account


@serde
@dataclass
class IAMEntities:
    iam_accounts_entities: Dict[str, IAMAccountEntities]
    iam_aws_managed_policies: Dict[str, IAMPolicy]

    @classmethod
    def load(cls, iam_accounts_entities: Dict[str, IAMAccountEntities]) -> 'IAMEntities':
        iam_aws_managed_policies: Dict[str, IAMPolicy] = {}
        # pop all managed aws policies from each account, and insert them to the iam_aws_managed_policies
        for iam_account_entities in iam_accounts_entities.values():
            iam_aws_managed_policies.update(iam_account_entities.pop_iam_managed_policies())

        return cls(iam_accounts_entities=iam_accounts_entities, iam_aws_managed_policies=iam_aws_managed_policies)

    def get_attached_iam_groups_for_iam_user(self, iam_user: IAMUser) -> List[IAMGroup]:
        iam_account_entities: Optional[IAMAccountEntities] = self.iam_accounts_entities.get(iam_user.get_account_id())
        if iam_account_entities:
            return iam_account_entities.get_attached_iam_groups_for_iam_user(iam_user)
        else:
            return []

    def get_iam_policy(self, policy_arn: str) -> IAMPolicy:
        """Function assumes that policy_arn is valid arn of existing IAMPolicy"""
        account_id = IAMPolicy.extract_aws_account_id_from_arn_of_iam_entity(policy_arn)
        if IAMAccountEntities.is_valid_aws_account_id(account_id):
            return self.iam_accounts_entities[account_id].iam_policies[policy_arn]
        else:
            return self.iam_aws_managed_policies[policy_arn]

    def yield_iam_users(self) -> Generator[IAMUser, None, None]:
        for iam_account_entities in self.iam_accounts_entities.values():
            for iam_user in iam_account_entities.iam_users.values():
                yield iam_user

    def yield_iam_roles(self) -> Generator[IAMRole, None, None]:
        for iam_account_entities in self.iam_accounts_entities.values():
            for iam_role in iam_account_entities.iam_roles.values():
                yield iam_role
