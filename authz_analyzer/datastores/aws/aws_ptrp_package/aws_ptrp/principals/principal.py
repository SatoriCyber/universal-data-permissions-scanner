import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Set

from aws_ptrp.ptrp_models.ptrp_model import AwsPrincipalType
from serde import field, serde

regex_saml_provider = re.compile(r"arn:aws:iam::([0-9]+):saml-provider/(.+)$")
regex_role_name = re.compile(r"arn:aws:iam::([0-9]+):role/(.+)$")
regex_iam_user = re.compile(r"arn:aws:iam::([0-9]+):user/(.+)$")
regex_federated_user = re.compile(r"arn:aws:sts::([0-9]+):federated-user/(.+)$")
regex_role_session = re.compile(r"arn:aws:sts::([0-9]+):assumed-role/(.+)/(.+)$")
regex_account_id = re.compile(r"([0-9]+)$")
regex_arn_account_id = re.compile(r"arn:aws:iam::([0-9]+):root$")
regex_aws_sso_reserved_role = re.compile(r"arn:aws:iam::([0-9]+):role/aws-reserved/sso.amazonaws.com/(.+)$")


def is_stmt_principal_relevant_to_resource(
    stmt_principal: 'Principal',
    resource_aws_account_id: str,
    resource_based_irrelevant_principal_types: Optional[Set[AwsPrincipalType]],
) -> bool:
    if (
        resource_based_irrelevant_principal_types
        and stmt_principal.principal_type in resource_based_irrelevant_principal_types
    ):
        return False
    # The below is unclear, seems like principal of AWS_ACCOUNT (like arn:aws:iam::([0-9]+):root) works only in cross-account access
    # although not clear evidence for that in the AWS docs, I couldn't makes it work for single account access
    # need to verify with AWS support
    if (
        stmt_principal.principal_type == AwsPrincipalType.AWS_ACCOUNT
        and resource_aws_account_id == stmt_principal.get_account_id()
    ):
        return False
    return True


class PrincipalBase(ABC):
    @abstractmethod
    def get_principal(self) -> 'Principal':
        pass


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
            or self.principal_type == AwsPrincipalType.ANONYMOUS_USER
        )
        return is_no_entity

    def is_all_principals(self) -> bool:
        return bool(self.principal_type == AwsPrincipalType.ALL_PRINCIPALS)

    def is_iam_user_principal(self) -> bool:
        return bool(self.principal_type == AwsPrincipalType.IAM_USER)

    def is_aws_account(self) -> bool:
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

    def is_principal_aws_sso_reserved_role(self) -> bool:
        return regex_aws_sso_reserved_role.match(self.get_arn()) is not None

    def is_iam_identity_center_user_principal(self) -> bool:
        return bool(self.principal_type == AwsPrincipalType.IAM_IDENTITY_CENTER_USER)

    def is_aws_sso_saml_session(self) -> bool:
        return bool(
            self.principal_type == AwsPrincipalType.SAML_SESSION
            and self.name.startswith("AWSSSO_")
            and self.name.endswith("DO_NOT_DELETE")
        )

    def contains(self, other: 'Principal') -> bool:
        # must not be ALL_PRINCIPALS (due to resolving all principal to other users)
        assert self.principal_type != AwsPrincipalType.ALL_PRINCIPALS

        # currently we don't have good solution in principal resolving of wildcard (*)
        # wildcard principal resolves to all possible entities (iam users, federated users, etc..) except for no_entity principals.
        # so the below is kind of a hack for that, means if policy contains wildcard principal it should ALSO resolves to
        # anonymous principal, and we want that a no entity principal will match by this anonymous principal
        if self.principal_type == AwsPrincipalType.ANONYMOUS_USER and other.is_no_entity_principal():
            # to cover the resolving of no_entity principals (like AWS_SERVICE)
            return True

        if self.principal_type == other.principal_type:
            if self.policy_principal_str == other.policy_principal_str:
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
    def load_anonymous_user(cls) -> "Principal":
        return Principal(
            principal_type=AwsPrincipalType.ANONYMOUS_USER,
            name="Anonymous user",
            policy_principal_str="Anonymous user",
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

    @staticmethod
    def _extract_name(path_and_name: str) -> str:
        """return the name from the last part of the arn (path & name).
        For example: path_and_name = '/path_to_role/nested_path/role_name_1' ->  role_name_1"""
        index_last_slash = path_and_name.rfind('/')
        if index_last_slash == -1:
            return path_and_name
        else:
            return path_and_name[index_last_slash + 1 :]

    @classmethod
    def load_from_stmt_aws(cls, principal_str: str) -> "Principal":
        # don't change the order here. for optimization to load_from_iam_role, load_from_iam_user
        # the function checks first the regex regex_role_name, regex_iam_user
        # another option is to create additional functions for each types, so both load_from_iam_role, load_from_iam_user
        # should call these functions and not the load_from_stmt_aws
        result = regex_role_name.match(principal_str)
        if result:
            name = Principal._extract_name(result.groups()[1])
            metadata = {'account-id': result.groups()[0], 'role-name': name}
            return Principal(
                principal_type=AwsPrincipalType.IAM_ROLE,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_iam_user.match(principal_str)
        if result:
            name = Principal._extract_name(result.groups()[1])
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
                'role-name': result.groups()[1],  # arn of role_session is without the role path
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
