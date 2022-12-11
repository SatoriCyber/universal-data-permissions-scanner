import json
from typing import Dict, Any, Optional, Type, List, Union
from dataclasses import dataclass
from enum import Enum
from pydantic import BaseModel, Field


class Effect(str, Enum):
    Deny = "Deny"
    Allow = "Allow"


class Statement(BaseModel):
    effect: Effect = Field(..., alias='Effect')
    sid: str = Field(..., alias='Sid')
    principal: Optional[Union[str, Dict[str, str]]] = Field(default=None, alias='Principal')
    action: Union[str, List[str]] = Field(..., alias='Action')
    resource: Union[str, List[str]] = Field(..., alias='Resource')
    # condition: TODO


class Policy(BaseModel):
    policy_name: str = Field(..., alias='PolicyName')
    policy_id: str = Field(..., alias='PolicyId')
    arn: str = Field(..., alias='Arn')
    default_version_id: str = Field(..., alias='DefaultVersionId')
    path: str = Field(..., alias='Path')
    description: Optional[str] = Field(default=None, alias='Description')
    attachment_count: int = Field(..., alias='AttachmentCount')
    permissions_boundary_usage_count: int = Field(..., alias='PermissionsBoundaryUsageCount')
    is_attachable: bool = Field(..., alias='IsAttachable')
