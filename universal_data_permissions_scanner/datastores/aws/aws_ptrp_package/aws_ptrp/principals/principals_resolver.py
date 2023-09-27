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
        not_principal_annotated: bool,
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

        accounts_with_root_principal_in_stmt_principals: Set[Optional[str]] = set()
        if not_principal_annotated:
            # Set will be used later to exclude cross account principals from "NotPrincipal" list,
            # if the root principal of the account is not in the list
            accounts_with_root_principal_in_stmt_principals = set(
                principal.get_account_id() for principal in stmt_principals if principal.is_aws_account()
            )

        for stmt_principal in stmt_principals:
            resolved_principals: Optional[Set[PrincipalBase]] = aws_principals.get_resolved_principals(
                stmt_name=stmt_name,
                stmt_parent_arn=stmt_parent_arn,
                policy_name=policy_name,
                stmt_principal=stmt_principal,
                all_stmt_principals=stmt_principals,
                not_principal_annotated=not_principal_annotated,
            )
            if resolved_principals:
                ret.update(resolved_principals)

        if not_principal_annotated:
            # Exclude all cross account principals from "NotPrincipal" list, if the root principal of the account is not in the list:
            ret = set(
                filter(
                    lambda resolved_principal: not (
                        resolved_principal.get_principal().get_account_id() != parent_aws_account_id
                        and resolved_principal.get_principal().get_account_id()
                        not in accounts_with_root_principal_in_stmt_principals
                    ),
                    ret,
                )
            )
            ret = aws_principals.get_all_principals_except_given(ret)

        logger.debug(
            "Resolved principals for parent arn %s, policy %s, stmt %s: %s",
            stmt_parent_arn,
            policy_name,
            stmt_name,
            ret,
        )
        return ret
