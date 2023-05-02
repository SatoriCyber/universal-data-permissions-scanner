from dataclasses import dataclass
from enum import Enum
from typing import List

from serde import field, serde


@serde(rename_all="pascalcase")
@dataclass
class Owner:
    display_name: str
    id: str = field(rename='ID')  # pylint: disable=invalid-name


class Permission(str, Enum):
    FULL_CONTROL = "FULL_CONTROL"
    WRITE = "WRITE"
    WRITE_ACP = "WRITE_ACP"
    READ = "READ"
    READ_ACP = "READ_ACP"


class GrantType(str, Enum):
    CANONICAL_USER = "CanonicalUser"
    AMAZON_CUSTOMER_BY_EMAIL = "AmazonCustomerByEmail"
    GROUP = "Group"


@serde(rename_all="pascalcase")
@dataclass
class Grantee:
    display_name: str
    type: GrantType
    id: str = field(rename='ID')  # pylint: disable=invalid-name


@serde(rename_all="pascalcase")
@dataclass
class Grants:
    grantee: Grantee
    permission: Permission


@serde(rename_all="pascalcase")
@dataclass
class S3BucketACL:
    owner: Owner
    grants: List[Grants]
