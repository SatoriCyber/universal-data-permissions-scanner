from dataclasses import dataclass
from logging import Logger
from typing import Dict, Generator, List, Optional, Set, Tuple

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.policy.policy_document import Effect, PolicyDocument, PolicyDocumentCtx
from aws_ptrp.iam.policy.policy_document_resolver import get_identity_based_resolver, get_resource_based_resolver
from aws_ptrp.principals import Principal
from aws_ptrp.principals.aws_principals import AwsPrincipals
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import (
    MethodOnStmtActionsResultType,
    MethodOnStmtActionsType,
    MethodOnStmtsActionsResult,
    ServiceActionType,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
    ServiceResourceType,
)
from aws_ptrp.services.resolved_stmt import ResolvedSingleStmt


@dataclass
class PolicyEvaluationExplicitDenyResult:
    difference_stmts_result_from_identity_policies: Optional[MethodOnStmtsActionsResult] = None
    difference_stmts_result_from_resource_policy: Optional[MethodOnStmtsActionsResult] = None

    @staticmethod
    def _yield_resolved_stmts(
        difference_stmts_results: Optional[MethodOnStmtsActionsResult],
        method_on_stmt_actions_type: MethodOnStmtActionsType,
        method_on_stmt_actions_result_type: MethodOnStmtActionsResultType,
    ) -> Generator[Tuple[ResolvedSingleStmt, MethodOnStmtActionsResultType], None, None]:
        if method_on_stmt_actions_type == MethodOnStmtActionsType.DIFFERENCE:
            if difference_stmts_results:
                for resolved_stmt_result in difference_stmts_results.resolved_stmt_results:
                    if resolved_stmt_result.result == method_on_stmt_actions_result_type:
                        yield (resolved_stmt_result.resolved_single_stmt, method_on_stmt_actions_result_type)

    def yield_resolved_stmts(
        self,
        method_on_stmt_actions_type: MethodOnStmtActionsType,
        method_on_stmt_actions_result_type_list: List[MethodOnStmtActionsResultType],
    ) -> Generator[Tuple[ResolvedSingleStmt, MethodOnStmtActionsResultType], None, None]:
        for method_on_stmt_actions_result_type in method_on_stmt_actions_result_type_list:
            yield from PolicyEvaluationExplicitDenyResult._yield_resolved_stmts(
                self.difference_stmts_result_from_resource_policy,
                method_on_stmt_actions_type,
                method_on_stmt_actions_result_type,
            )
            yield from PolicyEvaluationExplicitDenyResult._yield_resolved_stmts(
                self.difference_stmts_result_from_identity_policies,
                method_on_stmt_actions_type,
                method_on_stmt_actions_result_type,
            )


@dataclass
class PolicyEvaluationApplyResult:
    explicit_deny_result: PolicyEvaluationExplicitDenyResult


@dataclass
class PolicyEvaluationResult:
    target_resolver: Optional[ServiceResourcesResolverBase] = None
    policy_apply_result: Optional[PolicyEvaluationApplyResult] = None

    def get_target_resolver(self) -> Optional[ServiceResourcesResolverBase]:
        if self.target_resolver and self.target_resolver.is_empty() is False:
            return self.target_resolver
        return None

    def get_policy_apply_result(self) -> Optional[PolicyEvaluationApplyResult]:
        return self.policy_apply_result


@dataclass
class PolicyEvaluationsResult:
    result: Optional[PolicyEvaluationResult] = None
    result_cross_account: Optional[PolicyEvaluationResult] = None

    def get_target_resolver(self) -> Optional[ServiceResourcesResolverBase]:
        if self.result:
            return self.result.get_target_resolver()
        return None

    def get_policy_apply_result(self) -> Optional[PolicyEvaluationApplyResult]:
        if self.result:
            return self.result.get_policy_apply_result()
        return None

    def get_cross_account_policy_apply_result(self) -> Optional[PolicyEvaluationApplyResult]:
        if self.result_cross_account:
            return self.result_cross_account.get_policy_apply_result()
        return None


@dataclass
class PolicyEvaluation:
    logger: Logger
    identity_principal: Principal
    service_resource_type: ServiceResourceType
    identity_policies_service_resolver: Optional[ServiceResourcesResolverBase]
    resource_policy_service_resolver: Optional[ServiceResourcesResolverBase]
    # session_policies_service_resolver: List[ServiceResourcesResolverBase]
    # permission_boundary_policy_service_resolver: Optional[Dict[ServiceResourcesResolverBase]]
    aws_actions: AwsActions
    aws_principals: AwsPrincipals
    account_resources: AwsAccountResources

    def _apply_explicit_deny(
        self, target_policies_service_resolver: ServiceResourcesResolverBase
    ) -> PolicyEvaluationExplicitDenyResult:
        # subtract the explicit denies from the relevant policies
        ret = PolicyEvaluationExplicitDenyResult()
        if self.identity_policies_service_resolver:
            ret.difference_stmts_result_from_identity_policies = (
                target_policies_service_resolver.apply_method_on_stmts_actions(
                    MethodOnStmtActionsType.DIFFERENCE, self.identity_principal, self.identity_policies_service_resolver
                )
            )
        if self.resource_policy_service_resolver:
            ret.difference_stmts_result_from_resource_policy = (
                target_policies_service_resolver.apply_method_on_stmts_actions(
                    MethodOnStmtActionsType.DIFFERENCE, self.identity_principal, self.resource_policy_service_resolver
                )
            )
        return ret

    def _apply_policy_evaluation(
        self, target_policies_service_resolver: ServiceResourcesResolverBase
    ) -> PolicyEvaluationApplyResult:
        explicit_deny_result = self._apply_explicit_deny(target_policies_service_resolver)
        return PolicyEvaluationApplyResult(explicit_deny_result=explicit_deny_result)

    @staticmethod
    def _apply_intersection_on_service_resolvers(
        identity_principal: Principal,
        service_resolvers: List[Optional[ServiceResourcesResolverBase]],
    ) -> Optional[ServiceResourcesResolverBase]:
        if not service_resolvers or service_resolvers[0] is None or service_resolvers[0].is_empty():
            return None
        # No need to do INTERSECTION for the first entry with itself
        ret: ServiceResourcesResolverBase = service_resolvers[0]

        for service_resolver in service_resolvers[1:]:
            if service_resolver is None or service_resolver.is_empty():
                return None
            ret.apply_method_on_stmts_actions(
                MethodOnStmtActionsType.INTERSECTION, identity_principal, service_resolver
            )

        if ret.is_empty() is False:
            return ret
        return None

    @classmethod
    def _load(
        cls,
        logger: Logger,
        identity_principal: Principal,
        resource_policy_ctx: Optional[PolicyDocumentCtx],
        service_resource_type: ServiceResourceType,
        aws_actions: AwsActions,
        aws_principals: AwsPrincipals,
        account_resources: AwsAccountResources,
        principal_policies_ctx: List[PolicyDocumentCtx],
    ) -> 'PolicyEvaluation':
        identity_policies_service_resolver = cls._get_identity_policies_service_resolver(
            logger=logger,
            aws_actions=aws_actions,
            aws_principals=aws_principals,
            account_resources=account_resources,
            identity_principal=identity_principal,
            service_resource_type=service_resource_type,
            principal_policies_ctx=principal_policies_ctx,
            effect=Effect.Deny,
        )
        resource_policy_service_resolver = cls._get_resource_policy_service_resolver(
            logger=logger,
            aws_actions=aws_actions,
            aws_principals=aws_principals,
            account_resources=account_resources,
            service_resource_type=service_resource_type,
            resource_policy_ctx=resource_policy_ctx,
            effect=Effect.Deny,
        )

        policy_evaluation = cls(
            logger=logger,
            identity_principal=identity_principal,
            service_resource_type=service_resource_type,
            identity_policies_service_resolver=identity_policies_service_resolver,
            resource_policy_service_resolver=resource_policy_service_resolver,
            aws_actions=aws_actions,
            aws_principals=aws_principals,
            account_resources=account_resources,
        )
        return policy_evaluation

    @classmethod
    def _get_identity_policies_service_resolver(
        cls,
        logger: Logger,
        aws_actions: AwsActions,
        aws_principals: AwsPrincipals,
        account_resources: AwsAccountResources,
        identity_principal: Principal,
        service_resource_type: ServiceResourceType,
        principal_policies_ctx: List[PolicyDocumentCtx],
        effect: Effect,
    ) -> Optional[ServiceResourcesResolverBase]:
        allowed_service_action_types: Set[ServiceActionType] = set([service_resource_type])
        identity_policies_services_resolver: Optional[
            Dict[ServiceResourceType, ServiceResourcesResolverBase]
        ] = get_identity_based_resolver(
            logger=logger,
            policy_documents_ctx=principal_policies_ctx,
            identity_principal=identity_principal,
            aws_actions=aws_actions,
            aws_principals=aws_principals,
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
        aws_principals: AwsPrincipals,
        account_resources: AwsAccountResources,
        service_resource_type: ServiceResourceType,
        resource_policy_ctx: Optional[PolicyDocumentCtx],
        effect: Effect,
    ) -> Optional[ServiceResourcesResolverBase]:
        if resource_policy_ctx:
            resource_policy_service_resolver: Optional[ServiceResourcesResolverBase] = get_resource_based_resolver(
                logger=logger,
                policy_document=resource_policy_ctx.policy_document,
                service_resource_type=service_resource_type,
                resource_arn=resource_policy_ctx.parent_arn,
                resource_aws_account_id=resource_policy_ctx.parent_aws_account_id,
                aws_actions=aws_actions,
                aws_principals=aws_principals,
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
        aws_principals: AwsPrincipals,
        account_resources: AwsAccountResources,
        identity_principal: Principal,
        target_identity_policies_ctx: List[PolicyDocumentCtx],
        service_resource_type: ServiceResourceType,
        service_resource: ServiceResourceBase,
        principal_policies_ctx: List[PolicyDocumentCtx],
        # session_policies: List[PolicyDocument] = [],
        # permission_boundary_policy: Optional[PolicyDocument] = None,
        during_cross_account_checking_flow: bool = False,
    ) -> PolicyEvaluationResult:
        # in cross account, identity_principal (not the original principal!, but the last principal to be assumed in the path)
        # can has accesses to a resource only if the target_policy is a resource based policy
        policy_evaluation_result = PolicyEvaluationResult()
        if during_cross_account_checking_flow is False:
            if identity_principal.get_account_id() != service_resource.get_resource_account_id():
                return policy_evaluation_result

        target_policies_service_resolver = cls._get_identity_policies_service_resolver(
            logger,
            aws_actions,
            aws_principals,
            account_resources,
            identity_principal,
            service_resource_type,
            target_identity_policies_ctx,
            Effect.Allow,
        )
        if target_policies_service_resolver is None or target_policies_service_resolver.is_empty():
            return policy_evaluation_result
        policy_evaluation_result.target_resolver = target_policies_service_resolver

        resource_policy: Optional[PolicyDocument] = service_resource.get_resource_policy()
        if resource_policy:
            resource_policy_ctx: Optional[PolicyDocumentCtx] = PolicyDocumentCtx(
                policy_document=resource_policy,
                policy_name=service_resource.get_resource_name(),
                parent_arn=service_resource.get_resource_arn(),
                parent_aws_account_id=service_resource.get_resource_account_id(),
            )
        else:
            resource_policy_ctx = None

        policy_evaluation = cls._load(
            logger=logger,
            identity_principal=identity_principal,
            resource_policy_ctx=resource_policy_ctx,
            service_resource_type=service_resource_type,
            aws_actions=aws_actions,
            aws_principals=aws_principals,
            account_resources=account_resources,
            principal_policies_ctx=principal_policies_ctx,
        )

        policy_apply_result = policy_evaluation._apply_policy_evaluation(policy_evaluation_result.target_resolver)
        policy_evaluation_result.policy_apply_result = policy_apply_result
        return policy_evaluation_result

    @classmethod
    def run_target_policy_resource_based(
        cls,
        logger: Logger,
        aws_actions: AwsActions,
        aws_principals: AwsPrincipals,
        account_resources: AwsAccountResources,
        identity_principal: Principal,
        target_service_resource: ServiceResourceBase,
        service_resource_type: ServiceResourceType,
        principal_policies_ctx: List[PolicyDocumentCtx],
        # session_policies: List[PolicyDocument] = [],
        # permission_boundary_policy: Optional[PolicyDocument] = None,
    ) -> PolicyEvaluationsResult:
        policy_evaluations_result = PolicyEvaluationsResult()
        resource_policy: Optional[PolicyDocument] = target_service_resource.get_resource_policy()
        if resource_policy is None:
            return policy_evaluations_result

        resource_policy_ctx: PolicyDocumentCtx = PolicyDocumentCtx(
            policy_document=resource_policy,
            policy_name=target_service_resource.get_resource_name(),
            parent_arn=target_service_resource.get_resource_arn(),
            parent_aws_account_id=target_service_resource.get_resource_account_id(),
        )

        target_policy_service_resolver: Optional[
            ServiceResourcesResolverBase
        ] = cls._get_resource_policy_service_resolver(
            logger=logger,
            resource_policy_ctx=resource_policy_ctx,
            service_resource_type=service_resource_type,
            aws_actions=aws_actions,
            aws_principals=aws_principals,
            account_resources=account_resources,
            effect=Effect.Allow,
        )
        if target_policy_service_resolver is None or target_policy_service_resolver.is_empty():
            return policy_evaluations_result
        policy_evaluations_result.result = PolicyEvaluationResult()
        policy_evaluations_result.result.target_resolver = target_policy_service_resolver

        policy_evaluation = cls._load(
            logger=logger,
            identity_principal=identity_principal,
            resource_policy_ctx=resource_policy_ctx,
            service_resource_type=service_resource_type,
            aws_actions=aws_actions,
            aws_principals=aws_principals,
            account_resources=account_resources,
            principal_policies_ctx=principal_policies_ctx,
        )

        policy_apply_result = policy_evaluation._apply_policy_evaluation(
            policy_evaluations_result.result.target_resolver
        )
        policy_evaluations_result.result.policy_apply_result = policy_apply_result
        if policy_evaluations_result.result.target_resolver.is_empty():
            return policy_evaluations_result

        # for cross-account access, need to check that the identity in the trusted account has explicit allow to the resource in the trusting account
        if policy_evaluation.identity_principal.is_no_entity_principal():
            # identity is like AWS_SERVICE, no actual trusted account, just return the ret
            return policy_evaluations_result

        identity_principal_account_id: Optional[str] = identity_principal.get_account_id()
        if identity_principal_account_id == target_service_resource.get_resource_account_id():
            # not cross-account access but single account access
            return policy_evaluations_result

        # cross-account access checking
        policy_evaluations_result.result_cross_account = cls.run_target_policies_identity_based(
            logger=logger,
            aws_actions=aws_actions,
            aws_principals=aws_principals,
            account_resources=account_resources,
            identity_principal=identity_principal,
            target_identity_policies_ctx=principal_policies_ctx,
            service_resource_type=service_resource_type,
            service_resource=target_service_resource,
            principal_policies_ctx=principal_policies_ctx,
            during_cross_account_checking_flow=True,
        )

        # The final permissions for cross account, is the intersection between the two service resolvers (trusted & trusting accounts)
        service_resolvers: List[Optional[ServiceResourcesResolverBase]] = [
            policy_evaluations_result.result.target_resolver,
            policy_evaluations_result.result_cross_account.target_resolver,
        ]
        policy_evaluations_result.result.target_resolver = PolicyEvaluation._apply_intersection_on_service_resolvers(
            policy_evaluation.identity_principal, service_resolvers
        )
        return policy_evaluations_result
