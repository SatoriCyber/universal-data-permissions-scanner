import json
from typing import Dict, Any, Optional, Type, List, Union
from dataclasses import dataclass
from enum import Enum
from authz_analyzer.utils.aws.iam.policy.policy_document import PolicyDocument
from serde import deserialize, serialize, serde


@serde(rename_all = "pascalcase")
@dataclass
class GroupPolicy:
    group_name: str
    policy_name: str
    policy_document: PolicyDocument
