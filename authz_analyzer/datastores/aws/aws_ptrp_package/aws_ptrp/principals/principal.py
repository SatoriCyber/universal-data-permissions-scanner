import re
from dataclasses import dataclass
from typing import Dict, Optional

from aws_ptrp.ptrp_models.ptrp_model import AwsPrincipalType
from serde import field, serde

regex_saml_provider = re.compile(r"arn:aws:iam::([0-9]+):saml-provider/(.+)$")
regex_role_name = re.compile(r"arn:aws:iam::([0-9]+):role/(.+)$")
regex_iam_user = re.compile(r"arn:aws:iam::([0-9]+):user/(.+)$")
regex_federated_user = re.compile(r"arn:aws:sts::([0-9]+):federated-user/(.+)$")
regex_role_session = re.compile(r"arn:aws:sts::([0-9]+):assumed-role/(.+)/(.+)$")
regex_account_id = re.compile(r"([0-9]+)$")
regex_arn_account_id = re.compile(r"arn:aws:iam::([0-9]+):root$")


IAM_USER_ARN_ORIGINATED_FOR_FEDERATED_USER_KEY = "iam-user-arn-originated-for-federated-user"


@serde
@dataclass
class Principal:
    principal_type: AwsPrincipalType = field(skip=True)
    policy_principal_str: str = field(skip=True)
    name: str = field(skip=True)
    principal_metadata: Optional[Dict[str, str]] = field(skip=True)

    def __repr__(self):
        return f"Principal({self.get_arn()})"

    def __eq__(self, other):
        return self.get_arn() == other.get_arn()

    def __hash__(self):
        return hash(self.get_arn())

    @classmethod
    def from_policy_principal_str(cls, policy_principal_str: str) -> "Principal":
        return Principal.load_from_stmt_aws(policy_principal_str)

    def to_policy_principal_str(self) -> str:
        return self.policy_principal_str

    def get_name(self) -> str:
        return self.name

    def get_role_name(self) -> Optional[str]:
        if self.principal_metadata:
            return self.principal_metadata.get("role-name")
        return None

    def get_account_id(self) -> Optional[str]:
        if self.principal_metadata:
            return self.principal_metadata.get("account-id")
        return None

    def get_arn(self) -> str:
        if self.principal_type == AwsPrincipalType.AWS_ACCOUNT:
            account_id = self.principal_metadata['account-id']  # type: ignore
            return f"arn:aws:iam::{account_id}:root"
        else:
            return self.policy_principal_str

    def set_iam_user_originated_for_principal_federated(self, iam_user_arn: str):
        assert self.is_federated_user_principal() and self.principal_metadata is not None
        self.principal_metadata[IAM_USER_ARN_ORIGINATED_FOR_FEDERATED_USER_KEY] = iam_user_arn

    def is_no_entity_principal(
        self,
    ) -> bool:
        is_no_entity: bool = (
            # currently we don't support resolving format saml/web identity/canonical format
            # so, we treats it as no entity object (like aws service/federated etc..)
            self.principal_type == AwsPrincipalType.WEB_IDENTITY_SESSION
            or self.principal_type == AwsPrincipalType.SAML_SESSION
            or self.principal_type == AwsPrincipalType.CANONICAL_USER
            # real no entity principal
            or self.principal_type == AwsPrincipalType.AWS_SERVICE
            or self.principal_type == AwsPrincipalType.ALL_PRINCIPALS
        )
        return is_no_entity

    def is_all_principals(self) -> bool:
        return bool(self.principal_type == AwsPrincipalType.ALL_PRINCIPALS)

    def is_iam_user_principal(self) -> bool:
        return bool(self.principal_type == AwsPrincipalType.IAM_USER)

    def is_iam_user_account(self) -> bool:
        return bool(
            self.principal_type == AwsPrincipalType.AWS_ACCOUNT
            or self.principal_type == AwsPrincipalType.CANONICAL_USER
        )

    def is_federated_user_principal(self) -> bool:
        return bool(self.principal_type == AwsPrincipalType.AWS_STS_FEDERATED_USER_SESSION)

    def is_iam_role_principal(self) -> bool:
        return bool(self.principal_type == AwsPrincipalType.IAM_ROLE)

    def is_role_session_principal(self) -> bool:
        return bool(self.principal_type == AwsPrincipalType.ASSUMED_ROLE_SESSION)

    def contains(self, other: 'Principal') -> bool:
        if other.principal_type == AwsPrincipalType.ALL_PRINCIPALS:
            # any user/ anonymous user is contained by any type of self.principal
            return True

        if self.principal_type == other.principal_type:
            if self.policy_principal_str == other.policy_principal_str:
                return True

        if self.principal_type == AwsPrincipalType.ALL_PRINCIPALS:
            return True

        self_account_id = self.get_account_id()
        other_account_id = other.get_account_id()

        if self.is_iam_role_principal() and other.is_role_session_principal():
            return self.get_role_name() == other.get_role_name() and self_account_id == other_account_id

        elif other.is_federated_user_principal():
            if self.is_iam_user_principal():
                if other.principal_metadata:
                    other_originated_iam_user_arn: Optional[str] = other.principal_metadata.get(
                        IAM_USER_ARN_ORIGINATED_FOR_FEDERATED_USER_KEY, None
                    )
                else:
                    other_originated_iam_user_arn = None

                if other_originated_iam_user_arn is None:
                    raise Exception(
                        f"Unable to check contains {self} with {other}, missing the originated iam_user of the federated principal"
                    )
                return self.policy_principal_str == other_originated_iam_user_arn
            elif self.is_iam_user_account():
                if self_account_id == other_account_id:
                    return True

        elif self.is_iam_user_account():
            if self_account_id == other_account_id:
                return True

        return False

    @classmethod
    def load_from_iam_user(cls, principal_arn: str) -> "Principal":
        ret: Principal = Principal.load_from_stmt_aws(principal_arn)
        if ret.principal_type != AwsPrincipalType.IAM_USER:
            raise Exception(f"Failed to load Principal iam user from arn {principal_arn}")
        return ret

    @classmethod
    def load_from_iam_role(cls, principal_arn: str) -> "Principal":
        ret: Principal = Principal.load_from_stmt_aws(principal_arn)
        if ret.principal_type != AwsPrincipalType.IAM_ROLE:
            raise Exception(f"Failed to load Principal iam role from arn {principal_arn}")
        return ret

    @classmethod
    def load_from_iam_role_session(cls, principal_arn: str) -> "Principal":
        ret: Principal = Principal.load_from_stmt_aws(principal_arn)
        if ret.principal_type != AwsPrincipalType.ASSUMED_ROLE_SESSION:
            raise Exception(f"Failed to load Principal iam role session from arn {principal_arn}")
        return ret

    @classmethod
    def load_from_stmt_all(cls) -> "Principal":
        return Principal(
            principal_type=AwsPrincipalType.ALL_PRINCIPALS,
            name="All principals",
            policy_principal_str="*",
            principal_metadata=None,
        )

    @classmethod
    def load_from_stmt_canonical_user(cls, principal_str: str) -> "Principal":
        return Principal(
            principal_type=AwsPrincipalType.CANONICAL_USER,
            name=principal_str,
            policy_principal_str=principal_str,
            principal_metadata=None,
        )

    @classmethod
    def load_from_stmt_service(cls, principal_str: str) -> "Principal":
        return Principal(
            principal_type=AwsPrincipalType.AWS_SERVICE,
            name=principal_str,
            policy_principal_str=principal_str,
            principal_metadata=None,
        )

    @classmethod
    def load_from_stmt_federated(cls, principal_str: str) -> "Principal":
        result = regex_saml_provider.match(principal_str)
        if result:
            name = result.groups()[1]
            metadata = {'account-id': result.groups()[0], 'provider-name': name}
            return Principal(
                name=name,
                principal_type=AwsPrincipalType.SAML_SESSION,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )
        else:
            return Principal(
                principal_type=AwsPrincipalType.WEB_IDENTITY_SESSION,
                name=principal_str,
                policy_principal_str=principal_str,
                principal_metadata=None,
            )

    @classmethod
    def load_from_stmt_aws(cls, principal_str: str) -> "Principal":
        # don't change the order here. for optimization to load_from_iam_role, load_from_iam_user
        # the function checks first the regex regex_role_name, regex_iam_user
        # another option is to create additional functions for each types, so both load_from_iam_role, load_from_iam_user
        # should call these functions and not the load_from_stmt_aws
        result = regex_role_name.match(principal_str)
        if result:
            name = result.groups()[1]
            metadata = {'account-id': result.groups()[0], 'role-name': name}
            return Principal(
                principal_type=AwsPrincipalType.IAM_ROLE,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_iam_user.match(principal_str)
        if result:
            name = result.groups()[1]
            metadata = {'account-id': result.groups()[0], 'user-name': name}
            return Principal(
                principal_type=AwsPrincipalType.IAM_USER,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_account_id.match(principal_str)
        if result:
            name = result.groups()[0]
            metadata = {'account-id': name}
            return Principal(
                principal_type=AwsPrincipalType.AWS_ACCOUNT,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_arn_account_id.match(principal_str)
        if result:
            name = result.groups()[0]
            metadata = {'account-id': name}
            return Principal(
                principal_type=AwsPrincipalType.AWS_ACCOUNT,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_role_session.match(principal_str)
        if result:
            metadata = {
                'account-id': result.groups()[0],
                'role-name': result.groups()[1],
                'role-session-name': result.groups()[2],
            }
            name = result.groups()[2]
            return Principal(
                principal_type=AwsPrincipalType.ASSUMED_ROLE_SESSION,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_federated_user.match(principal_str)
        if result:
            name = result.groups()[1]
            metadata = {'account-id': result.groups()[0], 'federated-user': name}
            return Principal(
                principal_type=AwsPrincipalType.AWS_STS_FEDERATED_USER_SESSION,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        if principal_str == "*":
            return Principal(
                principal_type=AwsPrincipalType.ALL_PRINCIPALS,
                name="All principals",
                policy_principal_str=principal_str,
                principal_metadata=None,
            )

        raise Exception(f"Invalid principal: {principal_str}")
