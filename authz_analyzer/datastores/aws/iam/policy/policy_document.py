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


@serde(rename_all="pascalcase")
@dataclass
class PolicyDocument:
    statement: List[Statement]

    def is_contains_principal(self, principal_arn: PolicyPrincipal):
        return any(s.principal is not None and s.principal.contains(principal_arn) for s in self.statement)

    @staticmethod
    def fix_stmt_regex_to_valid_regex(stmt_regex: str) -> str:
        if stmt_regex == "*":
            return ".*" # convert to valid wildcard regex
            
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html
        # aws traits the '?' as regex '.' (any character)
        stmt_regex = stmt_regex.replace("?", ".")
        return stmt_regex
    
    def resolve(
        self,
        logger: Logger,
        account_actions: AwsAccountActions,
        account_resources: AwsAccountResources,
        allow_types_to_resolve: Set[ServiceType],
    ):
        for statement in self.statement:
            if statement.resource:
                statement.resolved_resource = ResourcesResolver.resolve_stmt_resource_regexes(
                    logger, statement.resource, account_resources, allow_types_to_resolve
                )
            if statement.action:
                statement.resolved_action = ActionsResolver.resolve_stmt_action_regexes(
                    logger, statement.action, account_actions, allow_types_to_resolve
                )
