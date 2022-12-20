import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Type, Union

from serde import deserialize, serde, serialize

from authz_analyzer.datastores.aws.iam.policy.policy_document import PolicyDocument


@serde(rename_all = "pascalcase")
@dataclass

class RolePolicy:
    role_name: str
    policy_name: str
    policy_document: PolicyDocument
