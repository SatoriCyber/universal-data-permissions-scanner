from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, List

from aws_ptrp.utils.serde import serde_enum_field
from serde import field, serde
from serde.se import to_dict  # pylint: disable=import-error #type: ignore


def sort_list(in_list: List[Any]) -> List[Any]:
    return sorted(in_list)


def serialize_list(in_list: List[Any]) -> List[Any]:
    return [to_dict(x) for x in sort_list(in_list)]


class AwsPtrpNoteType(Enum):
    """Types of note"""

    POLICY_STMT_DENY_WITH_CONDITION = auto()
    POLICY_STMT_SKIPPING_DENY_WITH_S3_NOT_RESOURCE = auto()
    IAM_IDENTITY_CENTER_USER_DESCRIPTION = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other):
        return self.value == other.value

    def __ne__(self, other):
        return not self.value == other.value

    def __lt__(self, other) -> bool:
        return bool(self.value < other.value)


@serde
@dataclass
class AwsPtrpNodeNote:
    """Note information to be used for node in a PTRP line"""

    note: str
    note_type: AwsPtrpNoteType = serde_enum_field(AwsPtrpNoteType)

    def __repr__(self):
        return f"{self.note_type}: {self.note}"

    def __ne__(self, other):
        return self.note_type != other.note_type or self.note != other.note

    def __lt__(self, other) -> bool:
        if self.note_type != other.note_type:
            return bool(self.note_type < other.note_type)
        else:
            return bool(self.note < other.note)


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

    def __ne__(self, other):
        return not self.value == other.value

    def __lt__(self, other) -> bool:
        return bool(self.value < other.value)


class AwsPrincipalType(Enum):
    """Types of AWS Principal"""

    AWS_ACCOUNT = auto()
    IAM_ROLE = auto()
    ASSUMED_ROLE_SESSION = auto()
    WEB_IDENTITY_SESSION = auto()
    SAML_SESSION = auto()
    IAM_USER = auto()
    IAM_IDENTITY_CENTER_USER = auto()
    CANONICAL_USER = auto()  # need to extract the account id
    AWS_STS_FEDERATED_USER_SESSION = auto()
    AWS_SERVICE = auto()
    ALL_PRINCIPALS = auto()
    ANONYMOUS_USER = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other):
        return self.value == other.value

    def __ne__(self, other):
        return not self.value == other.value

    def __lt__(self, other) -> bool:
        return bool(self.value < other.value)


class AwsPtrpPathNodeType(Enum):
    """Types of a single path node in PTRP line"""

    AWS_ACCOUNT = auto()
    AWS_SERVICE = auto()
    IAM_USER = auto()
    IAM_GROUP = auto()
    IAM_INLINE_POLICY = auto()
    IAM_POLICY = auto()
    IAM_ROLE = auto()
    IAM_IDENTITY_CENTER_USER = auto()
    IAM_IDENTITY_CENTER_GROUP = auto()
    PERMISSION_SET = auto()
    RESOURCE_POLICY = auto()
    ROLE_SESSION = auto()
    WEB_IDENTITY_SESSION = auto()
    SAML_SESSION = auto()
    FEDERATED_USER = auto()
    ANONYMOUS_USER = auto()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other):
        return self.value == other.value

    def __ne__(self, other):
        return not self.value == other.value

    def __lt__(self, other) -> bool:
        return bool(self.value < other.value)


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

    def __ne__(self, other):
        return not self.value == other.value

    def __lt__(self, other) -> bool:
        return bool(self.value < other.value)


@serde
@dataclass
class AwsPtrpPathNode:
    """A single path node in PTRP line that grant permissions to resource."""

    arn: str
    name: str
    type: AwsPtrpPathNodeType = serde_enum_field(AwsPtrpPathNodeType)
    notes: List[AwsPtrpNodeNote] = field(default=None, skip_if_default=True, serializer=serialize_list)

    def __repr__(self):
        return f"{self.type} {self.arn} {self.name} {self.notes}"

    def __ne__(self, other):
        return self.arn != other.arn or self.name != other.name or self.type != other.type or self.notes != other.notes

    def __lt__(self, other) -> bool:
        if self.arn != other.arn:
            return bool(self.arn < other.arn)
        elif self.name != other.name:
            return bool(self.name < other.name)
        elif self.type != other.type:
            return bool(self.type < other.type)
        else:
            return bool(self.notes < other.notes)


@serde
@dataclass
class AwsPtrpResource:
    """AWS PTRP resource, like S3 Bucket and its name"""

    name: str
    type: AwsPtrpResourceType = serde_enum_field(AwsPtrpResourceType)
    notes: List[AwsPtrpNodeNote] = field(default=None, skip_if_default=True, serializer=serialize_list)

    def __ne__(self, other):
        return self.name != other.name or self.type != other.type or self.notes != other.notes

    def __lt__(self, other) -> bool:
        if self.name != other.name:
            return bool(self.name < other.name)
        elif self.type != other.type:
            return bool(self.type < other.type)
        else:
            return bool(self.notes < other.notes)


@serde
@dataclass
class AwsPrincipal:
    """AWS Principal,
    For example, alon_user, IAM_USER, arn:aws:iam::105246207958:user/alon_user"""

    arn: str
    name: str
    type: AwsPrincipalType = serde_enum_field(AwsPrincipalType)
    notes: List[AwsPtrpNodeNote] = field(default=None, skip_if_default=True, serializer=serialize_list)

    def __ne__(self, other):
        return self.arn != other.arn or self.name != other.name or self.type != other.type or self.notes != other.notes

    def __lt__(self, other) -> bool:
        if self.arn != other.arn:
            return bool(self.arn < other.arn)
        elif self.name != other.name:
            return bool(self.name < other.name)
        elif self.type != other.type:
            return bool(self.type < other.type)
        else:
            return bool(self.notes < other.notes)


@serde
@dataclass
class AwsPtrpLine:
    """TheAWS PTRP Line. includes the edged from principal to resource, path nodes between with the granted permissions"""

    resource: AwsPtrpResource
    principal: AwsPrincipal
    action_permission_level: AwsPtrpActionPermissionLevel = serde_enum_field(AwsPtrpActionPermissionLevel)
    path_nodes: List[AwsPtrpPathNode] = field(default=None, skip_if_default=True)
    action_permissions: List[str] = field(default=None, skip_if_default=True, serializer=serialize_list)

    def __repr__(self):
        return f"{self.principal} {self.action_permission_level} {self.resource} {self.path_nodes}"

    def __ne__(self, other):
        return (
            self.resource != other.resource
            or self.principal != other.principal
            or self.action_permission_level != other.action_permission_level
            or self.path_nodes != other.path_nodes
            or self.action_permissions != other.action_permissions
        )

    def __lt__(self, other) -> bool:
        if self.resource != other.resource:
            return bool(self.resource < other.resource)
        elif self.principal != other.principal:
            return bool(self.principal < other.principal)
        elif self.action_permission_level != other.action_permission_level:
            return bool(self.action_permission_level < other.action_permission_level)
        elif self.path_nodes != other.path_nodes:
            return bool(self.path_nodes < other.path_nodes)
        else:
            return bool(self.action_permissions < other.action_permissions)
