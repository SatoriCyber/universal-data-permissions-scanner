from dataclasses import dataclass
from pydantic import BaseModel, Field


class PublicAccessBlockConfiguration(BaseModel):
    block_public_acls: bool = Field(..., alias='BlockPublicAcls')
    ignore_public_acls: bool = Field(..., alias='IgnorePublicAcls')
    block_public_policy: bool = Field(..., alias='BlockPublicPolicy')
    restrict_public_buckets: bool = Field(..., alias='RestrictPublicBuckets')