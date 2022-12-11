import json
from typing import Dict, Any, Optional, Type, List, Union
from dataclasses import dataclass
from enum import Enum
from pydantic import BaseModel, Field
from authz_analyzer.utils.aws.iam.policy.policy_document import PolicyDocument


class UserPolicy(BaseModel):
    user_name: str = Field(..., alias='UserName')
    policy_name: str = Field(..., alias='PolicyName')
    policy_document: PolicyDocument = Field(..., alias='PolicyDocument')
