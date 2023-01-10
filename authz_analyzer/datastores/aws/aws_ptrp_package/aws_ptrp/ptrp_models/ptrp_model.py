from dataclasses import dataclass
from enum import Enum, auto
from typing import List


class AwsPtrpResourceType(Enum):
    """Types of AWS resources supported by the PRTP"""

    S3_BUCKET = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


class AwsPrincipalType(Enum):
    """Types of AWS Principal"""

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

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


class AwsPtrpPathNodeType(Enum):
    """Types of a single path node in PTRP line"""

    AWS_ACCOUNT = auto()
    AWS_SERVICE = auto()
    IAM_USER = auto()
    IAM_GROUP = auto()
    IAM_INLINE_POLICY = auto()
    IAM_POLICY = auto()
    IAM_ROLE = auto()
    RESOURCE_POLICY = auto()
    ROLE_SESSION = auto()
    WEB_IDENTITY_SESSION = auto()
    SAML_SESSION = auto()
    FEDERATED_USER = auto()
    ALL_USERS = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


class AwsPtrpActionPermissionLevel(Enum):
    """Permission level of AWS action to a AWS resource"""

    READ = auto()
    WRITE = auto()
    FULL = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)


@dataclass
class AwsPtrpPathNode:
    """A single path node in PTRP line that grant permissions to resource."""

    arn: str
    name: str
    type: AwsPtrpPathNodeType
    note: str

    def __repr__(self):
        return f"{self.type} {self.arn} {self.name} {self.note}"


@dataclass
class AwsPtrpResource:
    """AWS PTRP resource, like S3 Bucket and its name"""

    name: str
    type: AwsPtrpResourceType


@dataclass
class AwsPrincipal:
    """AWS Principal,
    For example, alon_user, IAM_USER, arn:aws:iam::105246207958:user/alon_user"""

    arn: str
    type: AwsPrincipalType
    name: str


@dataclass
class AwsPtrpLine:
    """TheAWS PTRP Line. includes the edged from principal to resource, path nodes between with the granted permissions"""

    resource: AwsPtrpResource
    path_nodes: List[AwsPtrpPathNode]
    principal: AwsPrincipal
    action_permission_level: AwsPtrpActionPermissionLevel
    action_permissions: List[str]

    def __repr__(self):
        return f"{self.principal} {self.action_permission_level} {self.resource} {self.path_nodes}"
