import json
from dataclasses import dataclass, field
from logging import Logger
from pathlib import Path
from typing import Dict, List

from aws_ptrp.iam.iam_groups import IAMGroup, get_iam_groups
from aws_ptrp.iam.iam_policies import IAMPolicy, get_iam_policies
from aws_ptrp.iam.iam_roles import IAMRole, get_iam_roles
from aws_ptrp.iam.iam_users import IAMUser, get_iam_users
from boto3 import Session
from serde import from_dict, serde


@serde
@dataclass
class IAMEntities:
    iam_users: Dict[str, IAMUser] = field(default_factory=dict)  # key is user arn
    iam_groups: Dict[str, IAMGroup] = field(default_factory=dict)  # key is group arn
    iam_roles: Dict[str, IAMRole] = field(default_factory=dict)  # key is role arn
    iam_policies: Dict[str, IAMPolicy] = field(default_factory=dict)  # key is policy arn

    @classmethod
    def load_from_json_file(cls, _logger: Logger, file_path: Path) -> 'IAMEntities':
        with open(file_path, "r", encoding="utf-8") as file:
            analyzed_ctx_json = json.load(file)
            analyzed_ctx_loaded: 'IAMEntities' = from_dict(IAMEntities, analyzed_ctx_json)  # type: ignore
            return analyzed_ctx_loaded

    @classmethod
    def load_for_account(cls, logger: Logger, account_id: str, session: Session) -> 'IAMEntities':
        iam_entities = cls()
        iam_entities.update_for_account(logger, account_id, session)
        return iam_entities

    def get_attached_iam_groups_for_iam_user(self, iam_user: IAMUser) -> List[IAMGroup]:
        ret: List[IAMGroup] = []
        for iam_group in self.iam_groups.values():
            if iam_user.user_id in iam_group.group_user_ids:
                ret.append(iam_group)
        return ret

    def update_for_account(self, logger: Logger, account_id: str, session: Session):
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

        self.iam_users.update(iam_users)
        self.iam_groups.update(iam_groups)
        self.iam_roles.update(iam_roles)
        self.iam_policies.update(iam_policies)
