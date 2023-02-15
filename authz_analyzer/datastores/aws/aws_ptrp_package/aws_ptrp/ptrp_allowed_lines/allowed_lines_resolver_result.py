from dataclasses import dataclass
from logging import Logger
from typing import List, Optional

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.iam.policy.policy_document import PolicyDocumentCtx
from aws_ptrp.policy_evaluation import PolicyEvaluation, PolicyEvaluationResult, PolicyEvaluationsResult
from aws_ptrp.ptrp_allowed_lines.allowed_line import PtrpAllowedLine
from aws_ptrp.ptrp_allowed_lines.allowed_line_node_notes import (
    NodesNotes,
    get_nodes_notes_from_target_policies_identity_based,
    get_nodes_notes_from_target_policy_resource_based,
)
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import PoliciesNodeBase, PrincipalNodeBase, ResourceNode
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
        aws_actions: AwsActions,
        target_account_resources: AwsAccountResources,
        line: PtrpAllowedLine,
    ) -> Optional['PtrpAllowedLinesResolverResult']:
        resource_node: ResourceNode = line.resource_node
        is_target_policy_resource_based: bool = line.target_policy_node.is_resource_based_policy
        principal_to_policy: PrincipalNodeBase = line.get_principal_makes_the_request_to_resource()
        principal_policies_node_bases: List[PoliciesNodeBase] = line.get_principal_policies_bases()
        principal_policies_ctx: List[PolicyDocumentCtx] = PtrpAllowedLine.get_policies_ctx(
            principal_policies_node_bases, iam_entities.iam_policies
        )

        nodes_notes_all_services = NodesNotes()
        if (
            line.is_assuming_roles_allowed(
                logger, nodes_notes_all_services, aws_actions, target_account_resources, iam_entities.iam_policies
            )
            is False
        ):
            logger.info("line %s has roles nodes that are not allowed to be assumed", line)
            return None

        if (
            line.is_assuming_federated_user_allowed(
                logger, nodes_notes_all_services, aws_actions, target_account_resources, iam_entities.iam_policies
            )
            is False
        ):
            logger.info("line %s has federated nodes that are not allowed to be assumed", line)
            return None

        if is_target_policy_resource_based:
            policy_evaluations_result: PolicyEvaluationsResult = PolicyEvaluation.run_target_policy_resource_based(
                logger=logger,
                aws_actions=aws_actions,
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
                principal_policies_node_bases=principal_policies_node_bases,
                target_node_base=line.target_policy_node,
                resource_node_note=line.resource_node,
            )
            nodes_notes_all_services.extend(nodes_notes)
            return cls(target_resolver=target_resolver, nodes_notes=nodes_notes_all_services)
        else:
            target_identity_policy_ctx = PolicyDocumentCtx(
                policy_document=line.target_policy_node.policy_document,
                policy_name=line.target_policy_node.path_name,
                parent_arn=line.target_policy_node.path_arn,
            )
            policy_evaluation_result: PolicyEvaluationResult = PolicyEvaluation.run_target_policies_identity_based(
                logger=logger,
                aws_actions=aws_actions,
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
                principal_policies_node_bases=principal_policies_node_bases,
                target_node_base=line.target_policy_node,
                resource_node_note=line.resource_node,
            )
            nodes_notes_all_services.extend(nodes_notes)
            return cls(target_resolver=target_resolver, nodes_notes=nodes_notes_all_services)
