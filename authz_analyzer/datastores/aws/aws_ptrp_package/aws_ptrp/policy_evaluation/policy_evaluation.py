from dataclasses import dataclass
from logging import Logger
from typing import Dict, Generator, List, Optional, Set, Tuple

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.policy.policy_document import Effect, PolicyDocument
from aws_ptrp.iam.policy.policy_document_resolver import get_services_resources_resolver
from aws_ptrp.principals import Principal
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import ServiceActionType, ServiceResourceBase, ServiceResourcesResolverBase, ServiceResourceType


@dataclass
class PolicyEvaluation:
    logger: Logger
    identity_principal: Principal
    service_resource_type: ServiceResourceType
    service_resource: ServiceResourceBase
    target_policy_services_resolver: Dict[ServiceResourceType, ServiceResourcesResolverBase]
    identity_policies_services_resolver: List[Dict[ServiceResourceType, ServiceResourcesResolverBase]]
    resource_policy_services_resolver: Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]
    # session_policies_services_resolver: List[Dict[ServiceResourceType, ServiceResourcesResolverBase]]
    # permission_boundary_policy_services_resolver: Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]
    aws_actions: AwsActions
    account_resources: AwsAccountResources

    def _retain_target_policy_services_resolver(self):
        service_resource_types_to_delete = [
            x[0] for x in self.target_policy_services_resolver.items() if x[1].is_empty()
        ]
        for service_resource_type_to_delete in service_resource_types_to_delete:
            del self.target_policy_services_resolver[service_resource_type_to_delete]

    def _yield_services_resolves(
        self,
    ) -> Generator[Tuple[ServiceResourcesResolverBase, ServiceResourcesResolverBase], None, None]:
        for target_service_resource_type, target_service_resolver in self.target_policy_services_resolver.items():
            for identity_policies_service_resolver in self.identity_policies_services_resolver:
                service_resources_resolver = identity_policies_service_resolver.get(target_service_resource_type)
                if service_resources_resolver is None:
                    continue
                yield target_service_resolver, service_resources_resolver

            if self.resource_policy_services_resolver:
                resource_policy_service_resolver = self.resource_policy_services_resolver.get(
                    target_service_resource_type
                )
                if resource_policy_service_resolver is None:
                    continue
                yield target_service_resolver, resource_policy_service_resolver

    def _apply_explicit_deny(self):
        # subtract the explicit denies from the relevant policies
        for target_service_resolver, other_service_resolver in self._yield_services_resolves():
            target_service_resolver.subtract(self.identity_principal, other_service_resolver)

        self._retain_target_policy_services_resolver()

    def _apply_policy_evaluation(self):
        self._apply_explicit_deny()

    @classmethod
    def run(
        cls,
        logger: Logger,
        aws_actions: AwsActions,
        account_resources: AwsAccountResources,
        identity_principal: Principal,
        target_policy: PolicyDocument,
        is_target_policy_resource_based: bool,
        service_resource_type: ServiceResourceType,
        service_resource: ServiceResourceBase,
        identity_policies: List[PolicyDocument],
        # session_policies: List[PolicyDocument] = [],
        # permission_boundary_policy: Optional[PolicyDocument] = None,
    ) -> Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]:

        allowed_service_action_types: Set[ServiceActionType] = set([service_resource_type])
        if not is_target_policy_resource_based:
            # in cross account, identity_principal (not the original principal!, but the last principal to be assumed in the path)
            # can has accesses to a resource only if the target_policy is a resource based policy
            if identity_principal.get_account_id() != service_resource.get_resource_account_id():
                return None

        target_policy_services_resolver: Optional[
            Dict[ServiceResourceType, ServiceResourcesResolverBase]
        ] = get_services_resources_resolver(
            logger=logger,
            policy_document=target_policy,
            parent_resource_arn=service_resource.get_resource_arn(),
            identity_principal=identity_principal,
            aws_actions=aws_actions,
            account_resources=account_resources,
            effect=Effect.Allow,
            allowed_service_action_types=allowed_service_action_types,
        )
        if not target_policy_services_resolver:
            return None

        identity_policies_services_resolver: List[Dict[ServiceResourceType, ServiceResourcesResolverBase]] = []
        for identity_policy in identity_policies:
            identity_policy_services_resolver: Optional[
                Dict[ServiceResourceType, ServiceResourcesResolverBase]
            ] = get_services_resources_resolver(
                logger=logger,
                policy_document=identity_policy,
                parent_resource_arn=None,
                identity_principal=identity_principal,
                aws_actions=aws_actions,
                account_resources=account_resources,
                effect=Effect.Deny,
                allowed_service_action_types=allowed_service_action_types,
            )
            if identity_policy_services_resolver:
                identity_policies_services_resolver.append(identity_policy_services_resolver)

        resource_policy: Optional[PolicyDocument] = service_resource.get_resource_policy()
        if resource_policy:
            resource_policy_services_resolver: Optional[
                Dict[ServiceResourceType, ServiceResourcesResolverBase]
            ] = get_services_resources_resolver(
                logger=logger,
                policy_document=resource_policy,
                parent_resource_arn=service_resource.get_resource_arn(),
                identity_principal=identity_principal,
                aws_actions=aws_actions,
                account_resources=account_resources,
                effect=Effect.Deny,
                allowed_service_action_types=allowed_service_action_types,
            )
        else:
            resource_policy_services_resolver = None

        policy_evaluation = cls(
            logger=logger,
            identity_principal=identity_principal,
            service_resource_type=service_resource_type,
            service_resource=service_resource,
            target_policy_services_resolver=target_policy_services_resolver,
            identity_policies_services_resolver=identity_policies_services_resolver,
            resource_policy_services_resolver=resource_policy_services_resolver,
            aws_actions=aws_actions,
            account_resources=account_resources,
        )

        policy_evaluation._apply_policy_evaluation()

        if policy_evaluation.target_policy_services_resolver:
            return policy_evaluation.target_policy_services_resolver
        else:
            return None
