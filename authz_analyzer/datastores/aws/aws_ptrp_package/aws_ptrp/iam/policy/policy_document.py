from dataclasses import dataclass
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

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
    _principal: Optional[StmtPrincipals] = field(
        default=None,
        skip_if_default=True,
        deserializer=StmtPrincipals.from_stmt_document_principal,
        serializer=StmtPrincipals.to_stmt_document_principal,
        rename="Principal",
    )
    _not_principal: Optional[StmtPrincipals] = field(
        default=None,
        skip_if_default=True,
        deserializer=StmtPrincipals.from_stmt_document_principal,
        serializer=StmtPrincipals.to_stmt_document_principal,
        rename="NotPrincipal",
    )
    action: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    not_action: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    resource: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    not_resource: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    # just to verify if condition exists (To ignore Deny stmts with condition, to be on the strict side for the allowed permissions)
    # to revisit, once we will start to support condition
    condition: Optional[Dict[str, Any]] = field(default=None, skip_if_default=True)

    def get_principals(self) -> Tuple[List[Principal], bool]:
        lst: List[Principal] = []
        not_principal: bool = False
        if self._principal:
            lst.extend(self._principal.principals)
        elif self._not_principal:
            lst.extend(self._not_principal.principals)
            not_principal = True
        return lst, not_principal


@serde(rename_all="pascalcase")
@dataclass
class PolicyDocument:
    statement: List[Statement]

    def yield_stmt_principals(self, effect: Effect) -> Generator[Tuple[Principal, bool], None, None]:
        for stmt in self.statement:
            principals, not_principal = stmt.get_principals()
            if principals and stmt.effect == effect:
                for principal in principals:
                    yield principal, not_principal


@dataclass
class PolicyDocumentCtx:
    policy_document: PolicyDocument
    policy_name: Optional[str]
    parent_arn: str
