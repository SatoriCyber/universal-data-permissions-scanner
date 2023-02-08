from dataclasses import dataclass
from typing import Optional

from serde import field, serde


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
