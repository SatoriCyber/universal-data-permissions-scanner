from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from logging import Logger
from typing import Dict, List, Optional, Set, Union

from serde import field, serde

from authz_analyzer.datastores.aws.actions.account_actions import AwsAccountActions
from authz_analyzer.datastores.aws.actions.actions_resolver import ActionsResolver
from authz_analyzer.datastores.aws.actions.service_actions_resolver_base import ServiceActionsResolverBase
from authz_analyzer.datastores.aws.iam.policy.principal import PolicyPrincipal, PolicyPrincipals
from authz_analyzer.datastores.aws.resources.account_resources import AwsAccountResources
from authz_analyzer.datastores.aws.resources.resources_resolver import ResourcesResolver
from authz_analyzer.datastores.aws.resources.service_resources_resolver_base import ServiceResourcesResolverBase
from authz_analyzer.datastores.aws.services.service_base import ServiceType


class Effect(str, Enum):
    Deny = "Deny"
    Allow = "Allow"


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
    resolved_action: Optional[Dict[ServiceType, ServiceActionsResolverBase]] = field(default=None, skip=True)
    not_action: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    resource: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    resolved_resource: Optional[Dict[ServiceType, ServiceResourcesResolverBase]] = field(default=None, skip=True)
    not_resource: Optional[Union[str, List[str]]] = field(default=None, skip_if_default=True)
    # condition: TODO


class PolicyDocumentGetterBase(ABC):
    @property
    @abstractmethod
    def policy_documents(self) -> List['PolicyDocument']:
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
        stmt_regex = stmt_regex.replace("*", ".*") # convert to valid wildcard regex
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html
        # aws traits the '?' as regex '.' (any character)
        stmt_regex = stmt_regex.replace("?", ".")
        return stmt_regex
    
    def resolve(
        self,
        logger: Logger,
        parent_arn: str,
        account_actions: AwsAccountActions,
        account_resources: AwsAccountResources,
        allow_types_to_resolve: Set[ServiceType],
    ):
        for statement in self.statement:
            if statement.action is None or statement.resource is None:
                # missing action or resource on this stmt, noting to resolve
                continue
            
            resolved_action: Optional[Dict[ServiceType, ServiceActionsResolverBase]] = ActionsResolver.resolve_stmt_action_regexes(
                logger, statement.action, account_actions, allow_types_to_resolve
            )
            if resolved_action:
                logger.debug("Resolved actions for %s, stmt %s: %s", parent_arn, statement.sid, resolved_action)
                # has relevant resolved actions, Check the resolved resources
                resolved_service_actions = set([k for (k, v) in resolved_action.items()]) # type: ignore
                # need to resolve resources from the allowed service types which also appears from the resolved actions
                allow_types_to_resolve_for_resources = allow_types_to_resolve.intersection(resolved_service_actions)
                resolved_resource: Optional[Dict[ServiceType, ServiceResourcesResolverBase]] = ResourcesResolver.resolve_stmt_resource_regexes(
                    logger, statement.resource, account_resources, allow_types_to_resolve_for_resources
                )
                
                if resolved_resource:
                    logger.info("Resolved both resources & actions for %s, stmt %s: %s ; %s",parent_arn, statement.sid, resolved_action, resolved_resource)
                    statement.resolved_action = resolved_action
                    statement.resolved_resource = resolved_resource
                    