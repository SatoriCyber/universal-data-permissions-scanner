from dataclasses import dataclass
from typing import Optional

from aws_ptrp.principals import Principal


@dataclass
class AwsAssumeRole:
    role_arn: str
    external_id: Optional[str]

    def get_account_id(self) -> str:
        principal = Principal.load_from_iam_role(self.role_arn)
        account_id = principal.get_account_id()
        if not account_id:
            raise Exception(f"Unable to extract account id from role_arn {self.role_arn}")
        return account_id
