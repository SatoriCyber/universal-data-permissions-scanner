from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from logging import Logger
from typing import Dict, List, Optional, Set, Tuple, Union

from serde import field, serde

from authz_analyzer.datastores.aws.actions.account_actions import AwsAccountActions
from authz_analyzer.datastores.aws.actions.actions_resolver import ActionsResolver
from authz_analyzer.datastores.aws.iam.policy.effect import Effect
from authz_analyzer.datastores.aws.iam.policy.principal import PolicyPrincipal, PolicyPrincipals
from authz_analyzer.datastores.aws.resources.account_resources import AwsAccountResources
from authz_analyzer.datastores.aws.resources.resources_resolver import ResourcesResolver
from authz_analyzer.datastores.aws.services.service_base import (
    ServiceActionsResolverBase,
    ServiceResourcesResolverBase,
    ServiceType,
)


@serde(rename_all="pascalcase")
@dataclass
class Statement:
    effect: Effect
    sid: Optional[str] = field(default=None, skip_if_default=True)
    principal: Optional[PolicyPrincipals] = field(
        default=None,
        skip_if_default=True,
        deserializer=PolicyPrincipals.from_policy_document_principal,
        serializer=PolicyPrincipals.to_policy_document_principal,
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

    def is_contains_principal(self, principal_arn: PolicyPrincipal):
        return any(s.principal is not None and s.principal.contains(principal_arn) for s in self.statement)

    @staticmethod
    def fix_stmt_regex_to_valid_regex(stmt_regex: str) -> str:
        stmt_regex = stmt_regex.replace("*", ".*")  # convert to valid wildcard regex
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html
        # aws traits the '?' as regex '.' (any character)
        stmt_regex = stmt_regex.replace("?", ".")
        return stmt_regex

    def get_services_resources_resolver(
        self,
        logger: Logger,
        parent_arn: str,
        account_actions: AwsAccountActions,
        account_resources: AwsAccountResources,
        effect: Effect,
        allow_types_to_resolve: Set[ServiceType],
    ) -> Optional[Dict[ServiceType, ServiceResourcesResolverBase]]:

        all_stmts_service_resources_resolvers: Dict[ServiceType, ServiceResourcesResolverBase] = dict()
        for statement in self.statement:
            if statement.action is None or statement.resource is None:
                # missing action or resource on this stmt, noting to resolve
                continue
        
            if statement.effect != effect:
                continue

            single_stmt_service_actions_resolvers: Optional[
                Dict[ServiceType, ServiceActionsResolverBase]
            ] = ActionsResolver.resolve_stmt_action_regexes(
                logger, statement.action, account_actions, allow_types_to_resolve
            )

            if single_stmt_service_actions_resolvers:
                logger.debug(
                    "Resolved actions for %s, stmt %s: %s",
                    parent_arn,
                    statement.sid,
                    single_stmt_service_actions_resolvers,
                )
                # has relevant resolved actions, Check the resolved resources
                resolved_service_actions = set([k for (k, v) in single_stmt_service_actions_resolvers.items()])  # type: ignore
                # need to resolve resources from the allowed service types which also appears from the resolved actions
                allow_types_to_resolve_for_resources = allow_types_to_resolve.intersection(resolved_service_actions)
                single_stmt_service_resources_resolvers: Optional[
                    Dict[ServiceType, ServiceResourcesResolverBase]
                ] = ResourcesResolver.resolve_stmt_resource_regexes(
                    logger,
                    statement.resource,
                    account_resources,
                    allow_types_to_resolve_for_resources,
                    single_stmt_service_actions_resolvers,
                )

                if single_stmt_service_resources_resolvers:
                    for service_type, all_stmts_service_resolver in all_stmts_service_resources_resolvers.items():
                        curr_service_resolver: Optional[
                            ServiceResourcesResolverBase
                        ] = single_stmt_service_resources_resolvers.get(service_type)
                        if curr_service_resolver is not None:
                            all_stmts_service_resolver.merge(curr_service_resolver)

                    for service_type, single_stmt_service_resolver in single_stmt_service_resources_resolvers.items():
                        if all_stmts_service_resources_resolvers.get(service_type) is None:
                            all_stmts_service_resources_resolvers[service_type] = single_stmt_service_resolver

        if all_stmts_service_resources_resolvers:
            logger.debug("Resolved resources for %s: %s", parent_arn, all_stmts_service_resources_resolvers)
            return all_stmts_service_resources_resolvers
        else:
            return None
