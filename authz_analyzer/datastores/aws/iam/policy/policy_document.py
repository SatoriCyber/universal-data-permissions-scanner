from dataclasses import dataclass
from typing import List, Optional, Union
from serde import field, serde

from authz_analyzer.datastores.aws.iam.policy.effect import Effect
from authz_analyzer.datastores.aws.iam.policy.principal import StmtPrincipals


@serde(rename_all="pascalcase")
@dataclass
class Statement:
    effect: Effect
    sid: Optional[str] = field(default=None, skip_if_default=True)
    principal: Optional[StmtPrincipals] = field(
        default=None,
        skip_if_default=True,
        deserializer=StmtPrincipals.from_stmt_document_principal,
        serializer=StmtPrincipals.to_stmt_document_principal,
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
