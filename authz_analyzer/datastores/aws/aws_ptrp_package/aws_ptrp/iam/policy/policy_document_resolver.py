from logging import Logger
from typing import Dict, List, Optional, Set, Union

from aws_ptrp.actions.actions_resolver import ActionsResolver
from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.policy.effect import Effect
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.principals import Principal
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
    effect: Effect,
    aws_actions: AwsActions,
    account_resources: AwsAccountResources,
) -> Optional[AssumeRoleServiceResourcesResolver]:

    all_stmts_service_resources_resolvers: Dict[ServiceResourceType, ServiceResourcesResolverBase] = {}
    _services_resolver_for_policy_document(
        logger=logger,
        all_stmts_service_resources_resolvers=all_stmts_service_resources_resolvers,
        policy_document=role_trust_policy,
        parent_resource_arn=iam_role_arn,
        identity_principal=None,
        aws_actions=aws_actions,
        account_resources=account_resources,
        effect=effect,
        allowed_service_action_types=set([AssumeRoleService()]),
    )
    if all_stmts_service_resources_resolvers:
        ret_service_resources_resolver: Optional[
            ServiceResourcesResolverBase
        ] = all_stmts_service_resources_resolvers.get(AssumeRoleService())
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
    effect: Effect,
    aws_actions: AwsActions,
    account_resources: AwsAccountResources,
) -> Optional[ServiceResourcesResolverBase]:

    all_stmts_service_resources_resolvers: Dict[ServiceResourceType, ServiceResourcesResolverBase] = {}
    _services_resolver_for_policy_document(
        logger=logger,
        all_stmts_service_resources_resolvers=all_stmts_service_resources_resolvers,
        policy_document=policy_document,
        parent_resource_arn=resource_arn,
        identity_principal=None,
        aws_actions=aws_actions,
        account_resources=account_resources,
        effect=effect,
        allowed_service_action_types=set([service_resource_type]),
    )
    if all_stmts_service_resources_resolvers:
        return all_stmts_service_resources_resolvers.get(service_resource_type)
    return None


def get_identity_based_resolver(
    logger: Logger,
    policy_documents: List[PolicyDocument],
    identity_principal: Principal,
    effect: Effect,
    aws_actions: AwsActions,
    account_resources: AwsAccountResources,
    allowed_service_action_types: Optional[Set[ServiceActionType]] = None,
) -> Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]:

    all_stmts_service_resources_resolvers: Dict[ServiceResourceType, ServiceResourcesResolverBase] = {}
    for policy_document in policy_documents:
        _services_resolver_for_policy_document(
            logger=logger,
            all_stmts_service_resources_resolvers=all_stmts_service_resources_resolvers,
            policy_document=policy_document,
            parent_resource_arn=None,  # no need parent_resource the policy should includes the resources for each stmt
            identity_principal=identity_principal,
            aws_actions=aws_actions,
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
    parent_resource_arn: Optional[str],
    identity_principal: Optional[Principal],
    aws_actions: AwsActions,
    account_resources: AwsAccountResources,
    effect: Effect,
    allowed_service_action_types: Optional[Set[ServiceActionType]] = None,
):

    for statement in policy_document.statement:
        if statement.action is None:
            # missing action or resource on this stmt, noting to resolve
            continue

        if statement.effect != effect:
            continue

        if statement.principal:
            statement_principals: List[Principal] = statement.principal.principals
        elif identity_principal:
            statement_principals = [identity_principal]
        else:
            raise Exception(
                "Invalid principal input both statement.principal & outer param identity_principal are None"
            )

        if statement.resource:
            statement_resource: Union[str, List[str]] = statement.resource
        elif parent_resource_arn:
            statement_resource = parent_resource_arn
        else:
            raise Exception(
                f"Invalid resource input, both statement.resource & outer param parent_resource_arn are None - {statement}"
            )

        single_stmt_service_actions_resolvers: Optional[
            Dict[ServiceActionType, ServiceActionsResolverBase]
        ] = ActionsResolver.resolve_stmt_action_regexes(
            logger, statement.action, aws_actions, allowed_service_action_types
        )

        if single_stmt_service_actions_resolvers:
            logger.debug(
                "Resolved actions for stmt %s: %s",
                statement.sid,
                single_stmt_service_actions_resolvers,
            )
            # has relevant resolved actions, check the resolved resources
            resolved_services_action: Set[ServiceActionType] = set(single_stmt_service_actions_resolvers.keys())
            single_stmt_service_resources_resolvers: Optional[
                Dict[ServiceResourceType, ServiceResourcesResolverBase]
            ] = ResourcesResolver.resolve_stmt_resource_regexes(
                logger,
                statement_resource,
                account_resources,
                statement_principals,
                resolved_services_action,
                single_stmt_service_actions_resolvers,
            )

            if single_stmt_service_resources_resolvers:
                for service_type, all_stmts_service_resolver in all_stmts_service_resources_resolvers.items():
                    curr_service_resolver: Optional[
                        ServiceResourcesResolverBase
                    ] = single_stmt_service_resources_resolvers.get(service_type)
                    if curr_service_resolver is not None:
                        all_stmts_service_resolver.extend_resolved_stmts(curr_service_resolver.get_resolved_stmts())

                for service_type, single_stmt_service_resolver in single_stmt_service_resources_resolvers.items():
                    if all_stmts_service_resources_resolvers.get(service_type) is None:
                        all_stmts_service_resources_resolvers[service_type] = single_stmt_service_resolver
