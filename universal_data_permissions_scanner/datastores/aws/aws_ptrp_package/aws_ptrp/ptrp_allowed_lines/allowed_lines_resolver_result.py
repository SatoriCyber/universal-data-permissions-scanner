from dataclasses import dataclass
from logging import Logger
from typing import List, Optional

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.iam.policy.policy_document import PolicyDocumentCtx
from aws_ptrp.iam_identity_center.iam_identity_center_entities import IamIdentityCenterEntities
from aws_ptrp.policy_evaluation import PolicyEvaluation, PolicyEvaluationResult, PolicyEvaluationsResult
from aws_ptrp.principals.aws_principals import AwsPrincipals
from aws_ptrp.ptrp_allowed_lines.allowed_line import PtrpAllowedLine
from aws_ptrp.ptrp_allowed_lines.allowed_line_node_notes import (
    NodesNotes,
    get_nodes_notes_from_identity_center_user,
    get_nodes_notes_from_target_policies_identity_based,
    get_nodes_notes_from_target_policy_resource_based,
)
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import (
    PoliciesNodeBase,
    PrincipalAndPoliciesNode,
    PrincipalNodeBase,
    ResourceNode,
)
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import ServiceResourcesResolverBase


@dataclass
class PtrpAllowedLinesResolverResult:
    target_resolver: ServiceResourcesResolverBase
    nodes_notes: NodesNotes

    @classmethod
    def resolve(
        cls,
        logger: Logger,
        iam_entities: IAMEntities,
        iam_identity_center_entities: Optional[IamIdentityCenterEntities],
        aws_actions: AwsActions,
        aws_principals: AwsPrincipals,
        target_account_resources: AwsAccountResources,
        line: PtrpAllowedLine,
    ) -> Optional['PtrpAllowedLinesResolverResult']:
        resource_node: ResourceNode = line.resource_node
        is_target_policy_resource_based: bool = line.target_policy_node.is_resource_based_policy
        principal_node: PrincipalAndPoliciesNode = line.principal_node
        principal_to_policy: PrincipalNodeBase = line.get_principal_makes_the_request_to_resource()
        principal_policies_node_base: PoliciesNodeBase = line.get_principal_policies_base()
        principal_policies_ctx: List[PolicyDocumentCtx] = PtrpAllowedLine.get_policies_ctx(
            principal_policies_node_base, iam_entities
        )

        nodes_notes_all = NodesNotes()

        # Add a note for Identity Center User principal
        if principal_node.get_stmt_principal().is_iam_identity_center_user_principal():
            assert iam_identity_center_entities is not None
            nodes_notes = get_nodes_notes_from_identity_center_user(
                principal_node,
                iam_identity_center_entities.instance_arn,
                iam_identity_center_entities.account_id,
                iam_identity_center_entities.region,
            )
            nodes_notes_all.extend(nodes_notes)

        if (
            line.is_assuming_roles_allowed(
                logger,
                nodes_notes_all,
                aws_actions,
                aws_principals,
                target_account_resources,
                iam_entities,
            )
            is False
        ):
            logger.debug("line %s has roles nodes that are not allowed to be assumed", line)
            return None

        if (
            line.is_assuming_federated_user_allowed(
                logger,
                nodes_notes_all,
                aws_actions,
                aws_principals,
                target_account_resources,
                iam_entities,
            )
            is False
        ):
            logger.info("line %s has federated nodes that are not allowed to be assumed", line)
            return None

        if is_target_policy_resource_based:
            policy_evaluations_result: PolicyEvaluationsResult = PolicyEvaluation.run_target_policy_resource_based(
                logger=logger,
                aws_actions=aws_actions,
                aws_principals=aws_principals,
                account_resources=target_account_resources,
                identity_principal=principal_to_policy.get_stmt_principal(),
                target_service_resource=resource_node.base,
                service_resource_type=resource_node.service_resource_type,
                principal_policies_ctx=principal_policies_ctx,
            )
            target_resolver: Optional[ServiceResourcesResolverBase] = policy_evaluations_result.get_target_resolver()
            if not target_resolver:
                return None

            nodes_notes = get_nodes_notes_from_target_policy_resource_based(
                policy_evaluations_result=policy_evaluations_result,
                service_name=resource_node.service_resource_type.get_service_name(),
                principal_policies_node_base=principal_policies_node_base,
                target_node_base=line.target_policy_node,
                resource_node_note=line.resource_node,
            )
            nodes_notes_all.extend(nodes_notes)
            return cls(target_resolver=target_resolver, nodes_notes=nodes_notes_all)
        else:
            target_identity_policy_ctx = line.target_policy_node.policy_document_ctx
            policy_evaluation_result: PolicyEvaluationResult = PolicyEvaluation.run_target_policies_identity_based(
                logger=logger,
                aws_actions=aws_actions,
                aws_principals=aws_principals,
                account_resources=target_account_resources,
                identity_principal=principal_to_policy.get_stmt_principal(),
                target_identity_policies_ctx=[target_identity_policy_ctx],
                service_resource=resource_node.base,
                service_resource_type=resource_node.service_resource_type,
                principal_policies_ctx=principal_policies_ctx,
            )
            target_resolver = policy_evaluation_result.get_target_resolver()
            if not target_resolver:
                return None

            nodes_notes = get_nodes_notes_from_target_policies_identity_based(
                policy_evaluation_result=policy_evaluation_result,
                service_name=resource_node.service_resource_type.get_service_name(),
                principal_policies_node_base=principal_policies_node_base,
                target_node_base=line.target_policy_node,
                resource_node_note=line.resource_node,
            )
            nodes_notes_all.extend(nodes_notes)
            return cls(target_resolver=target_resolver, nodes_notes=nodes_notes_all)
