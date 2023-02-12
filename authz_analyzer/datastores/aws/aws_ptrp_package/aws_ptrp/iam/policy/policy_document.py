from dataclasses import dataclass
from typing import Any, Dict, Generator, List, Optional, Union

from aws_ptrp.iam.policy.effect import Effect
from aws_ptrp.principals.principal import Principal
from serde import field, serde


@serde
@dataclass
class StmtPrincipals:
    stmt_document_principal: Union[str, Dict[str, Union[str, List[str]]]]
    principals: List[Principal] = field(skip=True)

    def to_stmt_document_principal(self) -> Union[Optional[Any], str, Dict[str, Union[str, List[str]]]]:
        if self is None:
            return None
        return self.stmt_document_principal

    @classmethod
    def from_stmt_document_principal(
        cls, stmt_document_principal: Union[str, Dict[str, Union[str, List[str]]]]
    ) -> "StmtPrincipals":
        principals: List[Principal] = []
        if isinstance(stmt_document_principal, str):
            if stmt_document_principal == "*":
                principals = [Principal.load_from_stmt_all()]
            else:
                raise Exception(f"Invalid principal: {stmt_document_principal}")
        elif isinstance(stmt_document_principal, dict):
            for principal_type, principal_value in stmt_document_principal.items():
                values: List[str] = principal_value if isinstance(principal_value, list) else [str(principal_value)]
                for v in values:
                    if principal_type == "AWS":
                        principals.append(Principal.load_from_stmt_aws(v))
                    elif principal_type == "CanonicalUser":
                        principals.append(Principal.load_from_stmt_canonical_user(v))
                    elif principal_type == "Federated":
                        principals.append(Principal.load_from_stmt_federated(v))
                    elif principal_type == "Service":
                        principals.append(Principal.load_from_stmt_service(v))

            if len(principals) == 0:
                raise Exception(f"Invalid type of principal: {stmt_document_principal}")
        else:
            raise Exception(
                f"Invalid type of principal: {stmt_document_principal}, type: {type(stmt_document_principal)}"
            )

        return StmtPrincipals(principals=principals, stmt_document_principal=stmt_document_principal)


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
    _action: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True, rename="Action")
    _not_action: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True, rename="NotAction")
    resource: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    not_resource: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    # just to verify if condition exists (To ignore Deny stmts with condition, to be on the strict side for the allowed permissions)
    # to revisit, once we will start to support condition
    condition: Optional[Dict[str, Any]] = field(default=None, skip_if_default=True)

    def get_actions(self) -> Union[str, List[str]]:
        actions: List[str] = []
        if self._action:
            actions = self._action if isinstance(self._action, list) else [self._action]
        elif self._not_action:
            actions = self._not_action if isinstance(self._not_action, list) else [self._not_action]
        else:
            raise Exception("No Action or NotAction in statement")
        return actions

    def is_not_action_in_statement(self) -> bool:
        if self._action:
            return False
        elif self._not_action:
            return True
        else:
            raise Exception("No Action or NotAction in statement")


@serde(rename_all="pascalcase")
@dataclass
class PolicyDocument:
    statement: List[Statement]

    def yield_stmt_principals(self, effect: Effect) -> Generator[Principal, None, None]:
        for stmt in self.statement:
            if stmt.principal and stmt.effect == effect:
                for principal in stmt.principal.principals:
                    yield principal


@dataclass
class PolicyDocumentCtx:
    policy_document: PolicyDocument
    policy_name: Optional[str]
    parent_arn: str
