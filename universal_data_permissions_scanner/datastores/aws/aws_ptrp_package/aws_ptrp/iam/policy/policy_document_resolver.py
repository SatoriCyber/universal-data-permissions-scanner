from logging import Logger
from typing import Dict, List, Optional, Set

from aws_ptrp.actions.actions_resolver import ActionsResolver
from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.policy.effect import Effect
from aws_ptrp.iam.policy.policy_document import PolicyDocument, PolicyDocumentCtx
from aws_ptrp.principals import Principal, PrincipalBase
from aws_ptrp.principals.aws_principals import AwsPrincipals
from aws_ptrp.principals.principals_resolver import PrincipalsResolver
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.resources.resources_resolver import ResourcesResolver
from aws_ptrp.services import (
    ServiceActionsResolverBase,
    ServiceActionType,
    ServiceResourcesResolverBase,
    ServiceResourceType,
)
from aws_ptrp.services.assume_role.assume_role_resources import AssumeRoleServiceResourcesResolver
from aws_ptrp.services.assume_role.assume_role_service import AssumeRoleService


def get_role_trust_resolver(
    logger: Logger,
    role_trust_policy: PolicyDocument,
    iam_role_arn: str,
    iam_role_aws_account_id: str,
    effect: Effect,
    aws_actions: AwsActions,
    aws_principals: AwsPrincipals,
    account_resources: AwsAccountResources,
) -> Optional[AssumeRoleServiceResourcesResolver]:
    all_stmts_service_resources_resolvers: Dict[ServiceResourceType, ServiceResourcesResolverBase] = {}
    service_resource_type: ServiceResourceType = AssumeRoleService()

    _services_resolver_for_policy_document(
        logger=logger,
        all_stmts_service_resources_resolvers=all_stmts_service_resources_resolvers,
        policy_document=role_trust_policy,
        parent_arn=iam_role_arn,
        parent_aws_account_id=iam_role_aws_account_id,
        policy_name=None,
        identity_based_policy_principal=None,
        resource_based_policy_service_resource_type=service_resource_type,
        aws_actions=aws_actions,
        aws_principals=aws_principals,
        account_resources=account_resources,
        effect=effect,
        allowed_service_action_types=set([service_resource_type]),
    )
    if all_stmts_service_resources_resolvers:
        ret_service_resources_resolver: Optional[
            ServiceResourcesResolverBase
        ] = all_stmts_service_resources_resolvers.get(service_resource_type)
        if ret_service_resources_resolver and isinstance(
            ret_service_resources_resolver, AssumeRoleServiceResourcesResolver
        ):
            return ret_service_resources_resolver
    return None


def get_resource_based_resolver(
    logger: Logger,
    policy_document: PolicyDocument,
    service_resource_type: ServiceResourceType,
    resource_arn: str,
    resource_aws_account_id: str,
    effect: Effect,
    aws_actions: AwsActions,
    aws_principals: AwsPrincipals,
    account_resources: AwsAccountResources,
) -> Optional[ServiceResourcesResolverBase]:
    all_stmts_service_resources_resolvers: Dict[ServiceResourceType, ServiceResourcesResolverBase] = {}
    _services_resolver_for_policy_document(
        logger=logger,
        all_stmts_service_resources_resolvers=all_stmts_service_resources_resolvers,
        policy_document=policy_document,
        parent_arn=resource_arn,
        parent_aws_account_id=resource_aws_account_id,
        policy_name=None,
        resource_based_policy_service_resource_type=service_resource_type,
        identity_based_policy_principal=None,
        aws_actions=aws_actions,
        aws_principals=aws_principals,
        account_resources=account_resources,
        effect=effect,
        allowed_service_action_types=set([service_resource_type]),
    )
    if all_stmts_service_resources_resolvers:
        return all_stmts_service_resources_resolvers.get(service_resource_type)
    return None


def get_identity_based_resolver(
    logger: Logger,
    policy_documents_ctx: List[PolicyDocumentCtx],
    identity_principal: Principal,
    effect: Effect,
    aws_actions: AwsActions,
    aws_principals: AwsPrincipals,
    account_resources: AwsAccountResources,
    allowed_service_action_types: Optional[Set[ServiceActionType]] = None,
) -> Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]:
    all_stmts_service_resources_resolvers: Dict[ServiceResourceType, ServiceResourcesResolverBase] = {}
    for policy_document_ctx in policy_documents_ctx:
        _services_resolver_for_policy_document(
            logger=logger,
            all_stmts_service_resources_resolvers=all_stmts_service_resources_resolvers,
            policy_document=policy_document_ctx.policy_document,
            parent_arn=policy_document_ctx.parent_arn,
            parent_aws_account_id=policy_document_ctx.parent_aws_account_id,
            policy_name=policy_document_ctx.policy_name,
            resource_based_policy_service_resource_type=None,
            identity_based_policy_principal=identity_principal,
            aws_actions=aws_actions,
            aws_principals=aws_principals,
            account_resources=account_resources,
            effect=effect,
            allowed_service_action_types=allowed_service_action_types,
        )
    if all_stmts_service_resources_resolvers:
        return all_stmts_service_resources_resolvers
    else:
        return None


def _services_resolver_for_policy_document(
    logger: Logger,
    all_stmts_service_resources_resolvers: Dict[ServiceResourceType, ServiceResourcesResolverBase],
    policy_document: PolicyDocument,
    parent_arn: str,
    parent_aws_account_id: str,
    policy_name: Optional[str],
    resource_based_policy_service_resource_type: Optional[ServiceResourceType],
    identity_based_policy_principal: Optional[Principal],
    aws_actions: AwsActions,
    aws_principals: AwsPrincipals,
    account_resources: AwsAccountResources,
    effect: Effect,
    allowed_service_action_types: Optional[Set[ServiceActionType]] = None,
):
    # must be either resource_based_policy_service_resource_type is not None or identity_based_policy_principal is not None (not both)
    if (resource_based_policy_service_resource_type is None and identity_based_policy_principal is None) or (
        resource_based_policy_service_resource_type is not None and identity_based_policy_principal is not None
    ):
        raise Exception("Invalid input of resource_based_policy_service_resource_type, identity_based_policy_principal")

    for statement in policy_document.statement:
        if statement.effect != effect:
            continue

        # Get the statement resources
        statement_resources: Optional[List[str]] = statement.get_resources()
        if not statement_resources:
            if parent_arn:
                statement_resources = [parent_arn]
            else:
                raise Exception(
                    f"Invalid resource input, both statement.resource & outer param parent_resource_arn are None - {statement}"
                )

        # Resolve the statement principals
        stmt_principals: Optional[List[Principal]] = statement.get_principals()
        if not stmt_principals:
            if identity_based_policy_principal:
                stmt_principals = [identity_based_policy_principal]
            else:
                raise Exception(
                    "Invalid principal input both statement.principal & outer param identity_principal are None"
                )

        resolved_stmt_principals: Set[PrincipalBase] = PrincipalsResolver.resolve_stmt_principals(
            logger=logger,
            stmt_name=statement.sid,
            stmt_parent_arn=parent_arn,
            policy_name=policy_name,
            parent_aws_account_id=parent_aws_account_id,
            resource_based_policy_service_resource_type=resource_based_policy_service_resource_type,
            stmt_principals=stmt_principals,
            not_principal_annotated=statement.is_not_principal_in_statement(),
            aws_principals=aws_principals,
        )
        if not resolved_stmt_principals:
            continue

        # Resolve the statement actions
        single_stmt_service_actions_resolvers: Optional[
            Dict[ServiceActionType, ServiceActionsResolverBase]
        ] = ActionsResolver.resolve_stmt_action_regexes(
            logger,
            statement.get_actions(),
            statement.is_not_action_in_statement(),
            aws_actions,
            allowed_service_action_types,
        )
        if not single_stmt_service_actions_resolvers:
            continue

        logger.debug(
            "Resolved actions for stmt %s: %s",
            statement.sid,
            single_stmt_service_actions_resolvers,
        )

        # Resolve the statement resources
        resolved_services_action: Set[ServiceActionType] = set(single_stmt_service_actions_resolvers.keys())
        is_condition_stmt_exists: bool = statement.condition is not None
        single_stmt_service_resources_resolvers: Optional[
            Dict[ServiceResourceType, ServiceResourcesResolverBase]
        ] = ResourcesResolver.resolve_stmt_resource_regexes(
            logger=logger,
            stmt_name=statement.sid,
            stmt_parent_arn=parent_arn,
            policy_name=policy_name,
            is_condition_stmt_exists=is_condition_stmt_exists,
            stmt_resource=statement_resources,
            not_resource_annotated=statement.is_not_resource_in_statement(),
            account_resources=account_resources,
            resolved_stmt_principals=resolved_stmt_principals,
            resolved_stmt_services_action_types=resolved_services_action,
            service_action_stmt_resolvers=single_stmt_service_actions_resolvers,
        )

        # update the all_stmts_service_resources_resolvers with the current single stmt result
        if single_stmt_service_resources_resolvers:
            for service_type, single_stmt_service_resolver in single_stmt_service_resources_resolvers.items():
                all_stmts_service_resources_resolver: Optional[
                    ServiceResourcesResolverBase
                ] = all_stmts_service_resources_resolvers.get(service_type)

                if all_stmts_service_resources_resolver is not None:
                    all_stmts_service_resources_resolver.extend_resolved_stmts(
                        single_stmt_service_resolver.get_resolved_stmts()
                    )
                else:
                    all_stmts_service_resources_resolvers[service_type] = single_stmt_service_resolver
