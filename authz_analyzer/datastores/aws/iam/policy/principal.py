import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Union

from serde import field, serde

from authz_analyzer.datastores.aws.principals.principal_type import PrincipalType

regex_saml_provider = re.compile(r"^arn:aws:iam::([0-9]+):saml-provider/(.+)$")
regex_role_name = re.compile(r"^arn:aws:iam::([0-9]+):role/(.+)$")
regex_iam_user = re.compile(r"^arn:aws:iam::([0-9]+):user/(.+)$")
regex_federated_user = re.compile(r"^arn:aws:iam::([0-9]+):federated-user/(.+)$")
regex_role_session = re.compile(r"^arn:aws:sts::([0-9]+):assumed-role/(.+)/(.+)$")
regex_account_id = re.compile(r"^([0-9]+)$")
regex_arn_account_id = re.compile(r"^arn:aws:iam::([0-9]+):root$")


@serde
@dataclass
class StmtPrincipal:
    principal_type: PrincipalType = field(skip=True)
    policy_principal_str: str = field(skip=True)
    name: str = field(skip=True)
    principal_metadata: Optional[Dict[str, str]] = field(skip=True)

    def __repr__(self):
        return self.get_arn()

    def __eq__(self, other):
        return self.get_arn() == other.get_arn()

    def __hash__(self):
        return hash(self.get_arn())

    @classmethod
    def from_policy_principal_str(cls, policy_principal_str: str) -> "StmtPrincipal":
        return StmtPrincipal.load_aws(policy_principal_str)

    def to_policy_principal_str(self) -> str:
        return self.policy_principal_str

    def get_name(self) -> str:
        return self.name

    def get_arn(self) -> str:
        if self.principal_type == PrincipalType.AWS_ACCOUNT:
            account_id = self.principal_metadata['account-id']  # type: ignore
            return f"arn:aws:iam::{account_id}:root"
        elif self.principal_type == PrincipalType.ASSUMED_ROLE_SESSION:
            account_id = self.principal_metadata['account-id']  # type: ignore
            role_name = self.principal_metadata['role-name']  # type: ignore
            return f"arn:aws:iam::{account_id}:role/{role_name}"
        else:
            return self.policy_principal_str

    def is_no_entity_principal(
        self,
    ) -> bool:
        return (
            # currently we don't support resolving format saml/web identity/canonical format
            # so, we treats it as no entity object (like aws service/federated etc..)
            self.principal_type == PrincipalType.WEB_IDENTITY_SESSION
            or self.principal_type == PrincipalType.SAML_SESSION
            or self.principal_type == PrincipalType.CANONICAL_USER
            # real no entity principal
            or self.principal_type == PrincipalType.AWS_SERVICE
            or self.principal_type == PrincipalType.ALL_PRINCIPALS
        )

    def is_all_principals(self) -> bool:
        return self.principal_type == PrincipalType.ALL_PRINCIPALS

    def is_iam_user_principal(self) -> bool:
        return (
            self.principal_type == PrincipalType.AWS_ACCOUNT
            or self.principal_type == PrincipalType.IAM_USER
            or self.principal_type == PrincipalType.CANONICAL_USER
            or self.principal_type == PrincipalType.AWS_STS_FEDERATED_USER_SESSION
        )

    def is_role_principal(self) -> bool:
        return (
            self.principal_type == PrincipalType.IAM_ROLE or self.principal_type == PrincipalType.ASSUMED_ROLE_SESSION
        )

    def contains(self, other: 'StmtPrincipal') -> bool:
        if self.principal_type == PrincipalType.ALL_PRINCIPALS:
            return True
        if self.principal_type == other.principal_type:
            if self.policy_principal_str == other.policy_principal_str:
                return True

        if self.principal_type == PrincipalType.AWS_ACCOUNT:
            self_account_id = self.principal_metadata.get('account-id', None) if self.principal_metadata else None
            other_account_id = other.principal_metadata.get('account-id', None) if other.principal_metadata else None
            both_from_same_account_id = self_account_id is not None and self_account_id == other_account_id
            if both_from_same_account_id:
                return True

        return False

    @classmethod
    def load_all(cls) -> "StmtPrincipal":
        return StmtPrincipal(
            principal_type=PrincipalType.ALL_PRINCIPALS,
            name="All principals",
            policy_principal_str="*",
            principal_metadata=None,
        )

    @classmethod
    def load_canonical_user(cls, principal_str: str) -> "StmtPrincipal":
        return StmtPrincipal(
            principal_type=PrincipalType.CANONICAL_USER,
            name=principal_str,
            policy_principal_str=principal_str,
            principal_metadata=None,
        )

    @classmethod
    def load_service(cls, principal_str: str) -> "StmtPrincipal":
        return StmtPrincipal(
            principal_type=PrincipalType.AWS_SERVICE,
            name=principal_str,
            policy_principal_str=principal_str,
            principal_metadata=None,
        )

    @classmethod
    def load_federated(cls, principal_str: str) -> "StmtPrincipal":
        result = regex_saml_provider.match(principal_str)
        if result:
            name = result.groups()[1]
            metadata = {'account-id': result.groups()[0], 'provider-name': name}
            return StmtPrincipal(
                name=name,
                principal_type=PrincipalType.SAML_SESSION,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )
        else:
            return StmtPrincipal(
                principal_type=PrincipalType.WEB_IDENTITY_SESSION,
                name=principal_str,
                policy_principal_str=principal_str,
                principal_metadata=None,
            )

    @classmethod
    def load_aws(cls, principal_str: str) -> "StmtPrincipal":
        if principal_str == "*":
            return StmtPrincipal(
                principal_type=PrincipalType.ALL_PRINCIPALS,
                name="All principals",
                policy_principal_str=principal_str,
                principal_metadata=None,
            )

        result = regex_iam_user.match(principal_str)
        if result:
            name = result.groups()[1]
            metadata = {'account-id': result.groups()[0], 'user-name': name}
            return StmtPrincipal(
                principal_type=PrincipalType.IAM_USER,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_account_id.match(principal_str)
        if result:
            name = result.groups()[0]
            metadata = {'account-id': name}
            return StmtPrincipal(
                principal_type=PrincipalType.AWS_ACCOUNT,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_arn_account_id.match(principal_str)
        if result:
            name = result.groups()[0]
            metadata = {'account-id': name}
            return StmtPrincipal(
                principal_type=PrincipalType.AWS_ACCOUNT,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_role_name.match(principal_str)
        if result:
            name = result.groups()[1]
            metadata = {'account-id': result.groups()[0], 'role-name': name}
            return StmtPrincipal(
                principal_type=PrincipalType.IAM_ROLE,
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
            name = f"{result.groups()[1]}/{result.groups()[2]}"
            return StmtPrincipal(
                principal_type=PrincipalType.ASSUMED_ROLE_SESSION,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        result = regex_federated_user.match(principal_str)
        if result:
            name = result.groups()[1]
            metadata = {'account-id': result.groups()[0], 'federated-user': name}
            return StmtPrincipal(
                principal_type=PrincipalType.AWS_STS_FEDERATED_USER_SESSION,
                name=name,
                policy_principal_str=principal_str,
                principal_metadata=metadata,
            )

        raise BaseException(f"Invalid principal: {principal_str}")


@serde
@dataclass
class StmtPrincipals:
    stmt_document_principal: Union[str, Dict[str, Union[str, List[str]]]]
    principals: List[StmtPrincipal] = field(skip=True)

    def to_stmt_document_principal(self) -> Union[str, Dict[str, Union[str, List[str]]]]:
        if self is None:
            return None
        return self.stmt_document_principal

    @classmethod
    def from_stmt_document_principal(
        cls, stmt_document_principal: Union[str, Dict[str, Union[str, List[str]]]]
    ) -> "StmtPrincipals":
        principals: List[StmtPrincipal] = []
        if isinstance(stmt_document_principal, str):
            if stmt_document_principal == "*":
                principals = [StmtPrincipal.load_all()]
            else:
                raise BaseException(f"Invalid principal: {stmt_document_principal}")
        elif isinstance(stmt_document_principal, dict):
            for principal_type, principal_value in stmt_document_principal.items():
                values: List[str] = principal_value if type(principal_value) == list else [str(principal_value)]
                for v in values:
                    if principal_type == "AWS":
                        principals.append(StmtPrincipal.load_aws(v))
                    elif principal_type == "CanonicalUser":
                        principals.append(StmtPrincipal.load_canonical_user(v))
                    elif principal_type == "Federated":
                        principals.append(StmtPrincipal.load_federated(v))
                    elif principal_type == "Service":
                        principals.append(StmtPrincipal.load_service(v))

            if len(principals) == 0:
                raise BaseException(f"Invalid type of principal: {stmt_document_principal}")
        else:
            raise BaseException(
                f"Invalid type of principal: {stmt_document_principal}, type: {type(stmt_document_principal)}"
            )

        return StmtPrincipals(principals=principals, stmt_document_principal=stmt_document_principal)
