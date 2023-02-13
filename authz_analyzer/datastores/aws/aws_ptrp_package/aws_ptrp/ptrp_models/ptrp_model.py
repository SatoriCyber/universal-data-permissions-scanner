from dataclasses import dataclass
from enum import Enum, auto
from typing import List

from aws_ptrp.utils.serde import serde_enum_field
from serde import field, serde


class AwsPtrpNoteType(Enum):
    """Types of note"""

    POLICY_STMT_DENY_WITH_CONDITION = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other):
        return self.value == other.value


@serde
@dataclass
class AwsPtrpNodeNote:
    """Note information to be used for node in a PTRP line"""

    note: str
    note_type: AwsPtrpNoteType = serde_enum_field(AwsPtrpNoteType)

    def __repr__(self):
        return f"{self.note_type}: {self.note}"


class AwsPtrpResourceType(Enum):
    """Types of AWS resources supported by the PRTP"""

    S3_BUCKET = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other):
        return self.value == other.value


class AwsPrincipalType(Enum):
    """Types of AWS Principal"""

    AWS_ACCOUNT = auto()
    IAM_ROLE = auto()
    ASSUMED_ROLE_SESSION = auto()
    WEB_IDENTITY_SESSION = auto()
    SAML_SESSION = auto()
    IAM_USER = auto()
    CANONICAL_USER = auto()  # need to extract the account id
    AWS_STS_FEDERATED_USER_SESSION = auto()
    AWS_SERVICE = auto()
    ALL_PRINCIPALS = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other):
        return self.value == other.value


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

    def __eq__(self, other):
        return self.value == other.value


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

    def __eq__(self, other):
        return self.value == other.value


@serde
@dataclass
class AwsPtrpPathNode:
    """A single path node in PTRP line that grant permissions to resource."""

    arn: str
    name: str
    type: AwsPtrpPathNodeType = serde_enum_field(AwsPtrpPathNodeType)
    notes: List[AwsPtrpNodeNote] = field(default=None, skip_if_default=True)

    def __repr__(self):
        return f"{self.type} {self.arn} {self.name} {self.notes}"


@serde
@dataclass
class AwsPtrpResource:
    """AWS PTRP resource, like S3 Bucket and its name"""

    name: str
    type: AwsPtrpResourceType = serde_enum_field(AwsPtrpResourceType)
    notes: List[AwsPtrpNodeNote] = field(default=None, skip_if_default=True)


@serde
@dataclass
class AwsPrincipal:
    """AWS Principal,
    For example, alon_user, IAM_USER, arn:aws:iam::105246207958:user/alon_user"""

    arn: str
    name: str
    type: AwsPrincipalType = serde_enum_field(AwsPrincipalType)
    notes: List[AwsPtrpNodeNote] = field(default=None, skip_if_default=True)


@serde
@dataclass
class AwsPtrpLine:
    """TheAWS PTRP Line. includes the edged from principal to resource, path nodes between with the granted permissions"""

    resource: AwsPtrpResource
    principal: AwsPrincipal
    action_permission_level: AwsPtrpActionPermissionLevel = serde_enum_field(AwsPtrpActionPermissionLevel)
    path_nodes: List[AwsPtrpPathNode] = field(default=None, skip_if_default=True)
    action_permissions: List[str] = field(default=None, skip_if_default=True)

    def __repr__(self):
        return f"{self.principal} {self.action_permission_level} {self.resource} {self.path_nodes}"
