from logging import Logger
from typing import Dict, Optional, Set, List, Union

from aws_ptrp.iam.policy.principal import StmtPrincipal
from aws_ptrp.actions.account_actions import AwsAccountActions
from aws_ptrp.actions.actions_resolver import ActionsResolver
from aws_ptrp.iam.policy.effect import Effect
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.resources.resources_resolver import ResourcesResolver
from aws_ptrp.services.assume_role.assume_role_service import AssumeRoleServiceType
from aws_ptrp.services.assume_role.assume_role_resources import AssumeRoleServiceResourcesResolver
from aws_ptrp.services import (
    ServiceActionsResolverBase,
    ServiceResourcesResolverBase,
    ServiceActionType,
    ServiceResourceType,
)


def get_role_trust_resolver(
    logger: Logger,
    role_trust_policy: PolicyDocument,
    iam_role_arn: str,
    account_actions: AwsAccountActions,
    account_resources: AwsAccountResources,
) -> Optional[AssumeRoleServiceResourcesResolver]:

    ret_services_resources_resolver: Optional[
        Dict[ServiceResourceType, ServiceResourcesResolverBase]
    ] = get_services_resources_resolver(
        logger=logger,
        policy_document=role_trust_policy,
        parent_resource_arn=iam_role_arn,
        identity_principal=None,
        account_actions=account_actions,
        account_resources=account_resources,
        effect=Effect.Allow,
    )
    if ret_services_resources_resolver:
        ret_service_resources_resolver: Optional[ServiceResourcesResolverBase] = ret_services_resources_resolver.get(
            AssumeRoleServiceType()
        )
        if ret_service_resources_resolver and isinstance(
            ret_service_resources_resolver, AssumeRoleServiceResourcesResolver
        ):
            return ret_service_resources_resolver
    return None


def get_resource_based_resolver(
    logger: Logger,
    policy_document: PolicyDocument,
    service_resource_type: ServiceResourceType,
    account_actions: AwsAccountActions,
    account_resources: AwsAccountResources,
) -> Optional[ServiceResourcesResolverBase]:

    ret_services_resources_resolver: Optional[
        Dict[ServiceResourceType, ServiceResourcesResolverBase]
    ] = get_services_resources_resolver(
        logger=logger,
        policy_document=policy_document,
        parent_resource_arn=None,  # no need parent_resource the policy should includes the resources for each stmt
        identity_principal=None,
        account_actions=account_actions,
        account_resources=account_resources,
        effect=Effect.Allow,
    )
    if ret_services_resources_resolver:
        return ret_services_resources_resolver.get(service_resource_type)
    return None


def get_identity_based_resolver(
    logger: Logger,
    policy_document: PolicyDocument,
    identity_principal: StmtPrincipal,
    account_actions: AwsAccountActions,
    account_resources: AwsAccountResources,
) -> Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]:

    ret_services_resources_resolver: Optional[
        Dict[ServiceResourceType, ServiceResourcesResolverBase]
    ] = get_services_resources_resolver(
        logger=logger,
        policy_document=policy_document,
        parent_resource_arn=None,  # no need parent_resource the policy should includes the resources for each stmt
        identity_principal=identity_principal,
        account_actions=account_actions,
        account_resources=account_resources,
        effect=Effect.Allow,
    )
    return ret_services_resources_resolver


def get_services_resources_resolver(
    logger: Logger,
    policy_document: PolicyDocument,
    parent_resource_arn: Optional[str],
    identity_principal: Optional[StmtPrincipal],
    account_actions: AwsAccountActions,
    account_resources: AwsAccountResources,
    effect: Effect,
) -> Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]:

    all_stmts_service_resources_resolvers: Dict[ServiceResourceType, ServiceResourcesResolverBase] = dict()
    for statement in policy_document.statement:
        if statement.action is None:
            # missing action or resource on this stmt, noting to resolve
            continue

        if statement.effect != effect:
            continue

        if statement.principal:
            statement_principals: List[StmtPrincipal] = statement.principal.principals
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
                "Invalid resource input, both statement.resource & outer param parent_resource_arn are None"
            )

        single_stmt_service_actions_resolvers: Optional[
            Dict[ServiceActionType, ServiceActionsResolverBase]
        ] = ActionsResolver.resolve_stmt_action_regexes(logger, statement.action, account_actions)

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

    if all_stmts_service_resources_resolvers:
        return all_stmts_service_resources_resolvers
    else:
        return None
