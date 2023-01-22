from dataclasses import dataclass
from logging import Logger
from typing import Dict, Generator, List, Optional, Set

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.policy.policy_document import Effect, PolicyDocument
from aws_ptrp.iam.policy.policy_document_resolver import get_identity_based_resolver, get_resource_based_resolver
from aws_ptrp.principals import Principal
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import ServiceActionType, ServiceResourceBase, ServiceResourcesResolverBase, ServiceResourceType


@dataclass
class PolicyEvaluation:
    logger: Logger
    identity_principal: Principal
    service_resource_type: ServiceResourceType
    target_policies_service_resolver: ServiceResourcesResolverBase
    identity_policies_service_resolver: Optional[ServiceResourcesResolverBase]
    resource_policy_service_resolver: Optional[ServiceResourcesResolverBase]
    # session_policies_service_resolver: List[ServiceResourcesResolverBase]
    # permission_boundary_policy_service_resolver: Optional[Dict[ServiceResourcesResolverBase]]
    aws_actions: AwsActions
    account_resources: AwsAccountResources

    def _yield_services_resolves(
        self,
    ) -> Generator[ServiceResourcesResolverBase, None, None]:
        if self.identity_policies_service_resolver:
            yield self.identity_policies_service_resolver

        if self.resource_policy_service_resolver:
            yield self.resource_policy_service_resolver

    def _apply_explicit_deny(self):
        # subtract the explicit denies from the relevant policies
        for service_resolver_to_subtract in self._yield_services_resolves():
            self.target_policies_service_resolver.subtract(self.identity_principal, service_resolver_to_subtract)

    def _apply_policy_evaluation(self):
        self._apply_explicit_deny()

    def _run_policy_evaluation(self) -> Optional[ServiceResourcesResolverBase]:
        self._apply_policy_evaluation()
        if self.target_policies_service_resolver and self.target_policies_service_resolver.is_empty() is False:
            return self.target_policies_service_resolver
        else:
            return None

    @classmethod
    def _load(
        cls,
        logger: Logger,
        identity_principal: Principal,
        target_policies_service_resolver: ServiceResourcesResolverBase,
        resource_policy: Optional[PolicyDocument],
        resource_arn: str,
        service_resource_type: ServiceResourceType,
        aws_actions: AwsActions,
        account_resources: AwsAccountResources,
        identity_policies: List[PolicyDocument],
    ) -> 'PolicyEvaluation':
        identity_policies_service_resolver = cls._get_identity_policies_service_resolver(
            logger=logger,
            aws_actions=aws_actions,
            account_resources=account_resources,
            identity_principal=identity_principal,
            service_resource_type=service_resource_type,
            identity_policies=identity_policies,
            effect=Effect.Deny,
        )
        resource_policy_service_resolver = cls._get_resource_policy_service_resolver(
            logger=logger,
            aws_actions=aws_actions,
            account_resources=account_resources,
            service_resource_type=service_resource_type,
            resource_policy=resource_policy,
            resource_arn=resource_arn,
            effect=Effect.Deny,
        )

        policy_evaluation = cls(
            logger=logger,
            identity_principal=identity_principal,
            service_resource_type=service_resource_type,
            target_policies_service_resolver=target_policies_service_resolver,
            identity_policies_service_resolver=identity_policies_service_resolver,
            resource_policy_service_resolver=resource_policy_service_resolver,
            aws_actions=aws_actions,
            account_resources=account_resources,
        )
        return policy_evaluation

    @classmethod
    def _get_identity_policies_service_resolver(
        cls,
        logger: Logger,
        aws_actions: AwsActions,
        account_resources: AwsAccountResources,
        identity_principal: Principal,
        service_resource_type: ServiceResourceType,
        identity_policies: List[PolicyDocument],
        effect: Effect,
    ) -> Optional[ServiceResourcesResolverBase]:

        allowed_service_action_types: Set[ServiceActionType] = set([service_resource_type])
        identity_policies_services_resolver: Optional[
            Dict[ServiceResourceType, ServiceResourcesResolverBase]
        ] = get_identity_based_resolver(
            logger=logger,
            policy_documents=identity_policies,
            identity_principal=identity_principal,
            aws_actions=aws_actions,
            account_resources=account_resources,
            effect=effect,
            allowed_service_action_types=allowed_service_action_types,
        )

        if identity_policies_services_resolver:
            identity_policies_service_resolver: Optional[
                ServiceResourcesResolverBase
            ] = identity_policies_services_resolver.get(service_resource_type)
        else:
            identity_policies_service_resolver = None

        return identity_policies_service_resolver

    @classmethod
    def _get_resource_policy_service_resolver(
        cls,
        logger: Logger,
        aws_actions: AwsActions,
        account_resources: AwsAccountResources,
        service_resource_type: ServiceResourceType,
        resource_policy: Optional[PolicyDocument],
        resource_arn: str,
        effect: Effect,
    ) -> Optional[ServiceResourcesResolverBase]:
        if resource_policy:
            resource_policy_service_resolver: Optional[ServiceResourcesResolverBase] = get_resource_based_resolver(
                logger=logger,
                policy_document=resource_policy,
                service_resource_type=service_resource_type,
                resource_arn=resource_arn,
                aws_actions=aws_actions,
                account_resources=account_resources,
                effect=effect,
            )
        else:
            resource_policy_service_resolver = None
        return resource_policy_service_resolver

    @classmethod
    def run_target_policies_identity_based(
        cls,
        logger: Logger,
        aws_actions: AwsActions,
        account_resources: AwsAccountResources,
        identity_principal: Principal,
        target_identity_policies: List[PolicyDocument],
        service_resource_type: ServiceResourceType,
        service_resource: ServiceResourceBase,
        identity_policies: List[PolicyDocument],
        # session_policies: List[PolicyDocument] = [],
        # permission_boundary_policy: Optional[PolicyDocument] = None,
        during_cross_account_checking_flow: bool = False,
    ) -> Optional[ServiceResourcesResolverBase]:
        # in cross account, identity_principal (not the original principal!, but the last principal to be assumed in the path)
        # can has accesses to a resource only if the target_policy is a resource based policy
        if during_cross_account_checking_flow is False:
            if identity_principal.get_account_id() != service_resource.get_resource_account_id():
                return None

        target_policies_service_resolver = cls._get_identity_policies_service_resolver(
            logger,
            aws_actions,
            account_resources,
            identity_principal,
            service_resource_type,
            target_identity_policies,
            Effect.Allow,
        )
        if not target_policies_service_resolver:
            return None

        policy_evaluation = cls._load(
            logger=logger,
            identity_principal=identity_principal,
            target_policies_service_resolver=target_policies_service_resolver,
            resource_policy=service_resource.get_resource_policy(),
            resource_arn=service_resource.get_resource_arn(),
            service_resource_type=service_resource_type,
            aws_actions=aws_actions,
            account_resources=account_resources,
            identity_policies=identity_policies,
        )
        return policy_evaluation._run_policy_evaluation()

    @classmethod
    def run_target_policy_resource_based(
        cls,
        logger: Logger,
        aws_actions: AwsActions,
        account_resources: AwsAccountResources,
        identity_principal: Principal,
        target_service_resource: ServiceResourceBase,
        service_resource_type: ServiceResourceType,
        identity_policies: List[PolicyDocument],
        # session_policies: List[PolicyDocument] = [],
        # permission_boundary_policy: Optional[PolicyDocument] = None,
    ) -> Optional[ServiceResourcesResolverBase]:

        resource_policy: Optional[PolicyDocument] = target_service_resource.get_resource_policy()
        if resource_policy is None:
            return None

        target_policy_service_resolver: Optional[
            ServiceResourcesResolverBase
        ] = cls._get_resource_policy_service_resolver(
            logger=logger,
            resource_policy=resource_policy,
            resource_arn=target_service_resource.get_resource_arn(),
            service_resource_type=service_resource_type,
            aws_actions=aws_actions,
            account_resources=account_resources,
            effect=Effect.Allow,
        )
        if not target_policy_service_resolver:
            return None

        policy_evaluation = cls._load(
            logger=logger,
            identity_principal=identity_principal,
            target_policies_service_resolver=target_policy_service_resolver,
            service_resource_type=service_resource_type,
            resource_policy=resource_policy,
            resource_arn=target_service_resource.get_resource_arn(),
            aws_actions=aws_actions,
            account_resources=account_resources,
            identity_policies=identity_policies,
        )
        ret = policy_evaluation._run_policy_evaluation()
        if ret is None:
            return None

        identity_principal_account_id: Optional[str] = identity_principal.get_account_id()
        # for cross-account access, need to check that the identity in the trusted account has explicit allow to the resource in the trusting account
        if identity_principal_account_id is None:
            # identity is like AWS_SERVICE, no actual trusted account, just return the ret
            return ret
        if identity_principal_account_id == target_service_resource.get_resource_account_id():
            # not cross-account access
            return ret

        # cross-account access checking
        return cls.run_target_policies_identity_based(
            logger=logger,
            aws_actions=aws_actions,
            account_resources=account_resources,
            identity_principal=identity_principal,
            target_identity_policies=identity_policies,
            service_resource_type=service_resource_type,
            service_resource=target_service_resource,
            identity_policies=identity_policies,
            during_cross_account_checking_flow=True,
        )
