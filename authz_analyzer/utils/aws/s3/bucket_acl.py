from dataclasses import dataclass
from pydantic import BaseModel, Field
from typing import List
from enum import Enum


class Owner(BaseModel):
    display_name: str = Field(..., alias='DisplayName')
    id: str = Field(..., alias='ID')


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


class Grantee(BaseModel):
    display_name: str = Field(..., alias='DisplayName')
    id: str = Field(..., alias='ID')
    type: GrantType = Field(..., alias='Type')


class Grants(BaseModel):
    grantee: Grantee = Field(..., alias='Grantee')
    permission: Permission = Field(..., alias='Permission')


class S3BucketACL(BaseModel):
    owner: Owner = Field(..., alias='Owner')
    grants: List[Grants] = Field(..., alias='Grants')
