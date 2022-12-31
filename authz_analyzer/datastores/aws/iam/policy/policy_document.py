from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Tuple, Union

from serde import field, serde

from authz_analyzer.datastores.aws.actions.account_actions import AwsAccountActions
from authz_analyzer.datastores.aws.actions.actions_resolver import ActionsResolver
from authz_analyzer.datastores.aws.iam.policy.effect import Effect
from authz_analyzer.datastores.aws.iam.policy.principal import StmtPrincipals
from authz_analyzer.datastores.aws.resources.account_resources import AwsAccountResources
from authz_analyzer.datastores.aws.resources.resources_resolver import ResourcesResolver
from authz_analyzer.datastores.aws.services.role_trust.role_trust_principals import RoleTrustServicePrincipalsResolver
from authz_analyzer.datastores.aws.services.role_trust.role_trust_service import RoleTrustServiceType
from authz_analyzer.datastores.aws.services.role_trust.role_trust_actions import RoleTrustServiceActionsResolver
from authz_analyzer.datastores.aws.services import (
    ServiceActionsResolverBase,
    ServiceResourcesResolverBase,
    ServiceActionType,
    ServiceResourceType,
)


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


class PolicyDocumentGetterBase(ABC):
    @property
    @abstractmethod
    def inline_policy_documents_and_names(self) -> List[Tuple['PolicyDocument', str]]:
        pass

    @property
    @abstractmethod
    def parent_arn(self) -> str:
        pass


@serde(rename_all="pascalcase")
@dataclass
class PolicyDocument:
    statement: List[Statement]

    def get_role_trust_resolver(
        self,
        logger: Logger,
        parent_arn: str,
        account_actions: AwsAccountActions,
        effect: Effect,
    ) -> Optional[RoleTrustServicePrincipalsResolver]:
        role_trust_service_principal_resolver: Optional[RoleTrustServicePrincipalsResolver] = None
        role_trust_action_service_type = RoleTrustServiceType()

        for statement in self.statement:
            if statement.action is None or statement.principal is None:
                # missing principal stmt, noting to resolve
                continue

            if statement.effect != effect:
                continue

            single_stmt_service_actions_resolvers: Optional[
                Dict[ServiceActionType, ServiceActionsResolverBase]
            ] = ActionsResolver.resolve_stmt_action_regexes(logger, statement.action, account_actions)
            if single_stmt_service_actions_resolvers is None:
                continue

            res = single_stmt_service_actions_resolvers.get(role_trust_action_service_type)
            single_stmt_role_trust_actions_resolvers: Optional[RoleTrustServiceActionsResolver] = (
                res if res and isinstance(res, RoleTrustServiceActionsResolver) else None
            )
            if single_stmt_role_trust_actions_resolvers is None:
                continue

            logger.debug(
                "Resolved actions for %s, stmt %s: %s",
                parent_arn,
                statement.sid,
                single_stmt_service_actions_resolvers,
            )

            curr_role_trust_service_principal_resolver: RoleTrustServicePrincipalsResolver = (
                RoleTrustServicePrincipalsResolver.load_from_single_stmt(
                    logger, statement.principal, single_stmt_role_trust_actions_resolvers.resolved_actions
                )
            )
            if curr_role_trust_service_principal_resolver.is_empty():
                continue

            if role_trust_service_principal_resolver is None:
                role_trust_service_principal_resolver = curr_role_trust_service_principal_resolver
                continue
            else:
                role_trust_service_principal_resolver.add(curr_role_trust_service_principal_resolver)

        logger.debug("Resolved role trust for %s: %s", parent_arn, role_trust_service_principal_resolver)
        return role_trust_service_principal_resolver

    def get_services_resources_resolver(
        self,
        logger: Logger,
        parent_arn: str,
        account_actions: AwsAccountActions,
        account_resources: AwsAccountResources,
        effect: Effect,
    ) -> Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]:

        all_stmts_service_resources_resolvers: Dict[ServiceResourceType, ServiceResourcesResolverBase] = dict()
        for statement in self.statement:
            if statement.action is None or statement.resource is None:
                # missing action or resource on this stmt, noting to resolve
                continue

            if statement.effect != effect:
                continue

            single_stmt_service_actions_resolvers: Optional[
                Dict[ServiceActionType, ServiceActionsResolverBase]
            ] = ActionsResolver.resolve_stmt_action_regexes(logger, statement.action, account_actions)

            if single_stmt_service_actions_resolvers:
                logger.debug(
                    "Resolved actions for %s, stmt %s: %s",
                    parent_arn,
                    statement.sid,
                    single_stmt_service_actions_resolvers,
                )
                # has relevant resolved actions, check the resolved resources
                resolved_services_action: Set[ServiceActionType] = set(single_stmt_service_actions_resolvers.keys())
                single_stmt_service_resources_resolvers: Optional[
                    Dict[ServiceResourceType, ServiceResourcesResolverBase]
                ] = ResourcesResolver.resolve_stmt_resource_regexes(
                    logger,
                    statement.resource,
                    account_resources,
                    resolved_services_action,
                    single_stmt_service_actions_resolvers,
                )

                if single_stmt_service_resources_resolvers:
                    for service_type, all_stmts_service_resolver in all_stmts_service_resources_resolvers.items():
                        curr_service_resolver: Optional[
                            ServiceResourcesResolverBase
                        ] = single_stmt_service_resources_resolvers.get(service_type)
                        if curr_service_resolver is not None:
                            all_stmts_service_resolver.add_from_single_stmt(curr_service_resolver)

                    for service_type, single_stmt_service_resolver in single_stmt_service_resources_resolvers.items():
                        if all_stmts_service_resources_resolvers.get(service_type) is None:
                            all_stmts_service_resources_resolvers[service_type] = single_stmt_service_resolver

        if all_stmts_service_resources_resolvers:
            logger.debug("Resolved resources for %s: %s", parent_arn, all_stmts_service_resources_resolvers)
            return all_stmts_service_resources_resolvers
        else:
            return None
