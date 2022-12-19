import json
from typing import Dict, Any, Optional, Type, List, Union
from dataclasses import dataclass
from enum import Enum
from serde import deserialize, serialize, field, serde


@serde(rename_all = "pascalcase")
@dataclass
class Policy:
    policy_name: str
    policy_id: str
    arn: str
    default_version_id: str
    path: str
    attachment_count: int
    permissions_boundary_usage_count: int
    is_attachable: bool
    description: Optional[str] = field(default=None, skip_if_default=True)
