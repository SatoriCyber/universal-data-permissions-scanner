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
    sid: Optional[str] = Field(default=Optional, alias='Sid')
    principal: Optional[Union[str, Dict[str, str]]] = Field(default=Optional, alias='Principal')
    action: Union[str, List[str]] = Field(..., alias='Action')
    resource: Union[str, List[str]] = Field(..., alias='Resource')
    # condition: TODO


class PolicyDocument(BaseModel):
    statement: List[Statement] = Field(..., alias='Statement')
