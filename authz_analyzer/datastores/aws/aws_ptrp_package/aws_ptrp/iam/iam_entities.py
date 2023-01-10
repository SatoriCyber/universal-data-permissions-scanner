import json
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Dict

from serde import serde, from_dict
from boto3 import Session


from aws_ptrp.iam.iam_groups import IAMGroup, get_iam_groups
from aws_ptrp.iam.iam_policies import IAMPolicy, get_iam_policies
from aws_ptrp.iam.iam_roles import IAMRole, get_iam_roles
from aws_ptrp.iam.iam_users import IAMUser, get_iam_users


@serde
@dataclass
class IAMEntities:
    account_id: str
    iam_users: Dict[str, IAMUser]  # key is user arn
    iam_groups: Dict[str, IAMGroup]  # key is group arn
    iam_roles: Dict[str, IAMRole]  # key is role arn
    iam_policies: Dict[str, IAMPolicy]  # key is policy arn

    @classmethod
    def load_from_json_file(cls, _logger: Logger, file_path: Path) -> 'IAMEntities':
        with open(file_path, "r", encoding="utf-8") as file:
            analyzed_ctx_json = json.load(file)
            analyzed_ctx_loaded: 'IAMEntities' = from_dict(IAMEntities, analyzed_ctx_json)
            return analyzed_ctx_loaded

    @classmethod
    def load(cls, logger: Logger, aws_account_id: str, session: Session):
        logger.info(f"Start pulling IAM entities from aws account: {aws_account_id}...")
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
            account_id=aws_account_id,
            iam_users=iam_users,
            iam_groups=iam_groups,
            iam_roles=iam_roles,
            iam_policies=iam_policies,
        )
