import json
import re
from typing import Dict, Any, Optional, Type, List, Union, Tuple, AnyStr
from dataclasses import dataclass
from enum import Enum, auto
from serde import deserialize, serialize, field, serde


class AwsPrincipalType(Enum):
    AWS_ACCOUNT = auto()
    IAM_ROLE = auto()
    ASSUMED_ROLE_SESSION = auto()
    WEB_IDENTITY_SESSION = auto()
    SAML_SESSION = auto()
    IAM_USER = auto()
    CANONICAL_USER = auto()  # TODO need to extract the account id
    AWS_STS_FEDERATED_USER_SESSION = auto()
    AWS_SERVICE = auto()
    ALL_PRINCIPALS = auto()


regex_saml_provider = re.compile(r"^arn:aws:iam::([0-9]+):saml-provider/(.+)$")
regex_role_name = re.compile(r"^arn:aws:iam::([0-9]+):role/(.+)$")
regex_iam_user = re.compile(r"^arn:aws:iam::([0-9]+):user/(.+)$")
regex_federated_user = re.compile(r"^arn:aws:iam::([0-9]+):federated-user/(.+)$")
regex_role_session = re.compile(r"^arn:aws:sts::([0-9]+):assumed-role/(.+)/(.+)$")
regex_account_id = re.compile(r"^([0-9]+)$")
regex_arn_account_id = re.compile(r"^arn:aws:iam::([0-9]+):root$")


@serde
@dataclass    
class AwsPrincipal:
    principal_type: AwsPrincipalType = field(skip=True)
    principal_str: str = field(skip=True)
    principal_metadata: Optional[Dict[str, str]] = field(skip=True)

    @classmethod
    def from_iam_user(cls, principal_arn: str) -> "AwsPrincipal":
        return AwsPrincipal.load_aws(principal_arn)
         
    def to_iam_user(self) -> str:
        return self.principal_str

    def contains(self, other: 'AwsPrincipal') -> bool:
        if self.principal_type == AwsPrincipalType.ALL_PRINCIPALS:
            return True
        if self.principal_type == other.principal_type:
            if self.principal_str == other.principal_str:
                return True

        if self.principal_type == AwsPrincipalType.AWS_ACCOUNT:
            self_account_id = self.principal_metadata.get('account-id', None) if self.principal_metadata else None
            other_account_id = other.principal_metadata.get('account-id', None) if other.principal_metadata else None
            both_from_same_account_id = self_account_id is not None and self_account_id == other_account_id
            if both_from_same_account_id:
                return True

        return False

    @classmethod
    def load_all(cls) -> "AwsPrincipal":
        return AwsPrincipal(principal_type=AwsPrincipalType.ALL_PRINCIPALS, principal_str="*", principal_metadata=None)

    @classmethod
    def load_canonical_user(cls, principal_str: str) -> "AwsPrincipal":
        return AwsPrincipal(
            principal_type=AwsPrincipalType.CANONICAL_USER, principal_str=principal_str, principal_metadata=None
        )

    @classmethod
    def load_service(cls, principal_str: str) -> "AwsPrincipal":
        return AwsPrincipal(
            principal_type=AwsPrincipalType.AWS_SERVICE, principal_str=principal_str, principal_metadata=None
        )

    @classmethod
    def load_federated(cls, principal_str: str) -> "AwsPrincipal":
        result = regex_saml_provider.match(principal_str)
        if result:
            metadata = {'account-id': result.groups()[0], 'provider-name': result.groups()[1]}
            return AwsPrincipal(
                principal_type=AwsPrincipalType.SAML_SESSION, principal_str=principal_str, principal_metadata=metadata
            )
        else:
            return AwsPrincipal(
                principal_type=AwsPrincipalType.WEB_IDENTITY_SESSION,
                principal_str=principal_str,
                principal_metadata=None,
            )

    @classmethod
    def load_aws(cls, principal_str: str) -> "AwsPrincipal":
        if principal_str == "*":
            return AwsPrincipal(
                principal_type=AwsPrincipalType.ALL_PRINCIPALS, principal_str=principal_str, principal_metadata=None
            )

        result = regex_iam_user.match(principal_str)
        if result:
            metadata = {'account-id': result.groups()[0], 'user-name': result.groups()[1]}
            return AwsPrincipal(
                principal_type=AwsPrincipalType.IAM_USER, principal_str=principal_str, principal_metadata=metadata
            )

        result = regex_account_id.match(principal_str)
        if result:
            metadata = {'account-id': result.groups()[0]}
            return AwsPrincipal(
                principal_type=AwsPrincipalType.AWS_ACCOUNT, principal_str=principal_str, principal_metadata=metadata
            )

        result = regex_arn_account_id.match(principal_str)
        if result:
            metadata = {'account-id': result.groups()[0]}
            return AwsPrincipal(
                principal_type=AwsPrincipalType.AWS_ACCOUNT, principal_str=principal_str, principal_metadata=metadata
            )

        result = regex_role_name.match(principal_str)
        if result:
            metadata = {'account-id': result.groups()[0], 'role-name': result.groups()[1]}
            return AwsPrincipal(
                principal_type=AwsPrincipalType.IAM_ROLE, principal_str=principal_str, principal_metadata=metadata
            )

        result = regex_role_session.match(principal_str)
        if result:
            metadata = {
                'account-id': result.groups()[0],
                'role-name': result.groups()[1],
                'role-session-name': result.groups()[2],
            }
            return AwsPrincipal(
                principal_type=AwsPrincipalType.ASSUMED_ROLE_SESSION,
                principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_federated_user.match(principal_str)
        if result:
            metadata = {'account-id': result.groups()[0], 'federated-user': result.groups()[1]}
            return AwsPrincipal(
                principal_type=AwsPrincipalType.AWS_STS_FEDERATED_USER_SESSION,
                principal_str=principal_str,
                principal_metadata=metadata,
            )

        raise BaseException(f"Invalid principal: {principal_str}")


@serde
@dataclass
class AwsPolicyPrincipals:
    policy_document_principal: Union[str, Dict[str, Union[str, List[str]]]]
    principals: List[AwsPrincipal] = field(skip=True)

    def contains(self, other: AwsPrincipal):
        return any(x.contains(other) for x in self.principals)

    def to_policy_document_principal(self) -> Union[str, Dict[str, Union[str, List[str]]]]:
        if self is None:
            return None
        return self.policy_document_principal
        
    @classmethod
    def from_policy_document_principal(cls, policy_principal: Union[str, Dict[str, Union[str, List[str]]]]) -> "AwsPolicyPrincipals":
        principals: List[AwsPrincipal] = []
        if isinstance(policy_principal, str):
            if policy_principal == '*':
                principals = [AwsPrincipal.load_all()]
            else:
                raise BaseException(f"Invalid principal: {policy_principal}")
        elif isinstance(policy_principal, dict):
            for principal_type, principal_value in policy_principal.items():
                values: List[str] = principal_value if type(principal_value) == list else [str(principal_value)]
                for v in values:
                    if principal_type == "AWS":
                        principals.append(AwsPrincipal.load_aws(v))
                    elif principal_type == "CanonicalUser":
                        principals.append(AwsPrincipal.load_canonical_user(v))
                    elif principal_type == "Federated":
                        principals.append(AwsPrincipal.load_federated(v))
                    elif principal_type == "Service":
                        principals.append(AwsPrincipal.load_service(v))

            if len(principals) == 0:
                raise BaseException(f"Invalid type of principal: {policy_principal}")
        else:
            raise BaseException(f"Invalid type of principal: {policy_principal}, type: {type(policy_principal)}")

        return AwsPolicyPrincipals(principals=principals, policy_document_principal=policy_principal)
