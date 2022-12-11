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
    sid: Optional[str] = Field(default=None, alias='Sid')
    principal: Optional[Union[str, Dict[str, str]]] = Field(default=None, alias='Principal')
    action: Optional[Union[str, List[str]]] = Field(default=None, alias='Action')
    not_action: Optional[Union[str, List[str]]] = Field(default=None, alias='NotAction')
    resource: Optional[Union[str, List[str]]] = Field(default=None, alias='Resource')
    not_resource: Optional[Union[str, List[str]]] = Field(default=None, alias='NotResource')
    # condition: TODO


class PolicyDocument(BaseModel):
    statement: List[Statement] = Field(..., alias='Statement')
