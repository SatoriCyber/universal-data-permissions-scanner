import json
from typing import Dict, Any, Optional, Type, List, Union
from dataclasses import dataclass
from enum import Enum
from authz_analyzer.datastores.aws.iam.policy.policy_document import PolicyDocument
from serde import serde, deserialize, serialize


@serde(rename_all = "pascalcase")
@dataclass
class UserPolicy:
    user_name: str
    policy_name: str
    policy_document: PolicyDocument
