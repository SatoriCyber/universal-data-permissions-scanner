import json
from typing import Dict, Any, Optional, Type, List, Union
from dataclasses import dataclass
from enum import Enum
from authz_analyzer.datastores.aws.iam.policy.principal import AwsPolicyPrincipals, AwsPrincipal
from serde import deserialize, serialize, field, serde


class Effect(str, Enum):
    Deny = "Deny"
    Allow = "Allow"


@serde(rename_all="pascalcase")
@dataclass
class Statement:
    effect: Effect
    sid: Optional[str] = field(default=None, skip_if_default=True)
    principal: Optional[AwsPolicyPrincipals] = field(
        default=None,
        skip_if_default=True,
        deserializer=AwsPolicyPrincipals.from_policy_document_principal,
        serializer=AwsPolicyPrincipals.to_policy_document_principal,
    )
    action: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    not_action: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    resource: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    not_resource: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    # condition: TODO


@serde(rename_all="pascalcase")
@dataclass
class PolicyDocument:
    statement: List[Statement]

    def is_contains_principal(self, principal_arn: AwsPrincipal):
        return any(s.principal is not None and s.principal.contains(principal_arn) for s in self.statement)
