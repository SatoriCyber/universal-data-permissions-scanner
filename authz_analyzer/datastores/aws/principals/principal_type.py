
from enum import Enum, auto


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