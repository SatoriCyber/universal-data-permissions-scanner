from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from serde import field, serde


@serde(rename_all="pascalcase")
@dataclass
class Owner:
    id: str = field(rename='ID')  # pylint: disable=invalid-name
    display_name: Optional[str] = field(default=None, skip_if_default=True)


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
    type: GrantType
    id: str = field(rename='ID')  # pylint: disable=invalid-name
    display_name: Optional[str] = field(default=None, skip_if_default=True)


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
