from enum import Enum, auto
from authz_analyzer.models.model import IdentityType


class PrincipalType(Enum):
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

    def to_identity_type(self) -> IdentityType:
        if self == PrincipalType.AWS_ACCOUNT:
            return IdentityType.AWS_ACCOUNT
        elif self == PrincipalType.IAM_ROLE:
            return IdentityType.IAM_ROLE
        elif self == PrincipalType.ASSUMED_ROLE_SESSION:
            return IdentityType.ROLE_SESSION
        elif self == PrincipalType.WEB_IDENTITY_SESSION:
            return IdentityType.WEB_IDENTITY_SESSION
        elif self == PrincipalType.SAML_SESSION:
            return IdentityType.SAML_SESSION
        elif self == PrincipalType.IAM_USER:
            return IdentityType.IAM_USER
        elif self == PrincipalType.CANONICAL_USER:
            return IdentityType.AWS_ACCOUNT
        elif self == PrincipalType.AWS_STS_FEDERATED_USER_SESSION:
            return IdentityType.FEDERATED_USER
        elif self == PrincipalType.AWS_SERVICE:
            return IdentityType.AWS_SERVICE
        elif self == PrincipalType.ALL_PRINCIPALS:
            return IdentityType.ALL_USERS
        else:
            raise BaseException(f"unable to convert from {self} to IdentityType")
