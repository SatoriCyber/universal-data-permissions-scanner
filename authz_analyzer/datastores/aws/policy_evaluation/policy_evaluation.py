from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional

from authz_analyzer.datastores.aws.actions.account_actions import AwsAccountActions
from authz_analyzer.datastores.aws.resources.account_resources import AwsAccountResources
from authz_analyzer.datastores.aws.iam.policy.policy_document import Effect, PolicyDocument
from authz_analyzer.datastores.aws.iam.policy.policy_document_resolver import get_services_resources_resolver
from authz_analyzer.datastores.aws.iam.policy.principal import StmtPrincipal
from authz_analyzer.datastores.aws.services import (
    ServiceResourcesResolverBase,
    ServiceResourceType,
)


@dataclass
class PolicyEvaluation:
    logger: Logger
    identity_principal: StmtPrincipal
    target_policy_services_resolver: Dict[ServiceResourceType, ServiceResourcesResolverBase]
    identity_policies_services_resolver: List[Dict[ServiceResourceType, ServiceResourcesResolverBase]]
    resource_policy_services_resolver: Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]
    # session_policies_services_resolver: List[Dict[ServiceResourceType, ServiceResourcesResolverBase]]
    # permission_boundary_policy_services_resolver: Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]
    account_actions: AwsAccountActions
    account_resources: AwsAccountResources

    def _retain_target_policy_services_resolver(self):
        self.target_policy_services_resolver = dict(
            filter(lambda x: not x[1].is_empty(), self.target_policy_services_resolver.items())
        )

    def _apply_explicit_deny(self):
        pass

    #     # subtract the explicit deny from the resource based policies for this principal
    #     for service_resolver in self.target_policy_services_resolver.values():
    #         service_resolver.subtract_resource_based_policy_for_principal(self.stmt_principal)

    #     self._retain_target_policy_services_resolver()
    #     # subtract the explicit deny from each identity based policy
    #     for (
    #         identity_policy_services_resolver
    #     ) in self.identity_policies_services_resolver:  # type: Dict[ServiceResourceType, ServiceResourcesResolverBase]
    #         # Lookup every resolver for service_type that exists both in the target & the identity
    #         for (
    #             service_type,
    #             target_service_resolver,
    #         ) in (
    #             self.target_policy_services_resolver.items()
    #         ):  # type: Tuple[ServiceResourceType, ServiceResourcesResolverBase]
    #             identity_policy_service_resolver: Optional[
    #                 ServiceResourcesResolverBase
    #             ] = identity_policy_services_resolver.get(service_type)
    #             if identity_policy_service_resolver:
    #                 target_service_resolver.subtract(identity_policy_service_resolver)

    #     self._retain_target_policy_services_resolver()

    def _apply_policy_evaluation(self):
        self._apply_explicit_deny()

    @classmethod
    def run(
        cls,
        logger: Logger,
        account_actions: AwsAccountActions,
        account_resources: AwsAccountResources,
        identity_principal: StmtPrincipal,
        parent_resource_arn: Optional[str],
        target_policy: PolicyDocument,
        identity_policies: List[PolicyDocument],
        resource_policy: Optional[PolicyDocument],
        # session_policies: List[PolicyDocument] = [],
        # permission_boundary_policy: Optional[PolicyDocument] = None,
    ) -> Dict[ServiceResourceType, ServiceResourcesResolverBase]:

        target_policy_services_resolver: Optional[
            Dict[ServiceResourceType, ServiceResourcesResolverBase]
        ] = get_services_resources_resolver(
            logger=logger,
            policy_document=target_policy,
            parent_resource_arn=parent_resource_arn,
            identity_principal=identity_principal,
            account_actions=account_actions,
            account_resources=account_resources,
            effect=Effect.Allow,
        )
        if not target_policy_services_resolver:
            return dict()

        identity_policies_services_resolver: List[Dict[ServiceResourceType, ServiceResourcesResolverBase]] = []
        for identity_policy in identity_policies:
            identity_policy_services_resolver: Optional[
                Dict[ServiceResourceType, ServiceResourcesResolverBase]
            ] = get_services_resources_resolver(
                logger=logger,
                policy_document=identity_policy,
                parent_resource_arn=None,
                identity_principal=identity_principal,
                account_actions=account_actions,
                account_resources=account_resources,
                effect=Effect.Deny,
            )
            if identity_policy_services_resolver:
                identity_policies_services_resolver.append(identity_policy_services_resolver)

        if resource_policy:
            resource_policy_services_resolver: Optional[
                Dict[ServiceResourceType, ServiceResourcesResolverBase]
            ] = get_services_resources_resolver(
                logger=logger,
                policy_document=resource_policy,
                parent_resource_arn=parent_resource_arn,
                identity_principal=identity_principal,
                account_actions=account_actions,
                account_resources=account_resources,
                effect=Effect.Deny,
            )
        else:
            resource_policy_services_resolver = None

        policy_evaluation = cls(
            logger=logger,
            identity_principal=identity_principal,
            target_policy_services_resolver=target_policy_services_resolver,
            identity_policies_services_resolver=identity_policies_services_resolver,
            resource_policy_services_resolver=resource_policy_services_resolver,
            account_actions=account_actions,
            account_resources=account_resources,
        )

        policy_evaluation._apply_policy_evaluation()
        return policy_evaluation.target_policy_services_resolver
