import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Type, Union

from serde import deserialize, field, serde, serialize


@serde(rename_all="pascalcase")
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
