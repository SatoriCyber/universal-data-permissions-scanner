from dataclasses import dataclass
from logging import Logger
from typing import List, Optional, Set

from aws_ptrp.principals.aws_principals import AwsPrincipals
from aws_ptrp.principals.principal import Principal, PrincipalBase, is_stmt_principal_relevant_to_resource
from aws_ptrp.ptrp_models import AwsPrincipalType
from aws_ptrp.services import ServiceResourceType


def _filter_resource_based_stmt_principals(
    stmt_principals: List[Principal],
    resource_aws_account_id: str,
    resource_based_irrelevant_principal_types: Optional[Set[AwsPrincipalType]],
) -> List[Principal]:
    ret: List[Principal] = []
    for stmt_principal in stmt_principals:
        if is_stmt_principal_relevant_to_resource(
            stmt_principal, resource_aws_account_id, resource_based_irrelevant_principal_types
        ):
            ret.append(stmt_principal)
    return ret


@dataclass
class PrincipalsResolver:
    @classmethod
    def resolve_stmt_principals(
        cls,
        logger: Logger,
        stmt_name: Optional[str],
        stmt_parent_arn: str,
        policy_name: Optional[str],
        parent_aws_account_id: str,
        resource_based_policy_service_resource_type: Optional[ServiceResourceType],
        stmt_principals: List[Principal],
        aws_principals: AwsPrincipals,
    ) -> Set[PrincipalBase]:

        ret: Set[PrincipalBase] = set()
        if resource_based_policy_service_resource_type:
            resource_based_irrelevant_principal_types: Optional[
                Set[AwsPrincipalType]
            ] = resource_based_policy_service_resource_type.get_resource_based_policy_irrelevant_principal_types()
            stmt_principals = _filter_resource_based_stmt_principals(
                stmt_principals, parent_aws_account_id, resource_based_irrelevant_principal_types
            )
        for stmt_principal in stmt_principals:
            resolved_principals: Optional[Set[PrincipalBase]] = aws_principals.get_resolved_principals(
                stmt_name=stmt_name,
                stmt_parent_arn=stmt_parent_arn,
                policy_name=policy_name,
                stmt_principal=stmt_principal,
            )
            if resolved_principals:
                ret.update(resolved_principals)

        logger.debug(
            "Resolved principals for parent arn %s, policy %s, stmt %s: %s",
            stmt_parent_arn,
            policy_name,
            stmt_name,
            ret,
        )
        return ret
