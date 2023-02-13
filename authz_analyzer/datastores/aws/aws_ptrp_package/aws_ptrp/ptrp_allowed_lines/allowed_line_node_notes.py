from typing import List, Optional

from aws_ptrp.policy_evaluation import PolicyEvaluationApplyResult, PolicyEvaluationResult, PolicyEvaluationsResult
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import (
    NodeNote,
    NodeNoteBase,
    NodeNoteType,
    PoliciesAndNodeNoteBase,
)
from aws_ptrp.services import MethodOnStmtActionsResultType, MethodOnStmtActionsType


def _add_node_notes(
    policy_apply_result: PolicyEvaluationApplyResult,
    service_name: str,
    principal_policies_node_bases: List[PoliciesAndNodeNoteBase],
    target_node_base: NodeNoteBase,
    resource_node_note: NodeNoteBase,
):
    # For each resolved_stmt in the policy evaluation result, explicit deny result: check if there are stmt with Deny + condition
    for resolved_stmt in policy_apply_result.explicit_deny_result.yield_resolved_stmts(
        MethodOnStmtActionsType.DIFFERENCE, MethodOnStmtActionsResultType.IGNORE_METHOD_DIFFERENCE_CONDITION_EXISTS
    ):
        # build the node note params
        stmt_name = f"statement '{resolved_stmt.stmt_name}' in " if resolved_stmt.stmt_name else ''
        policy_name = (
            f"policy '{resolved_stmt.policy_name}'"
            if resolved_stmt.policy_name
            else f"policy of {resolved_stmt.stmt_parent_arn}"
        )
        attached_iam_policy = ""
        node_base_to_add: Optional[NodeNoteBase] = None

        # lookup the relevant node to add the note
        # first, check the target node base (prior to the resource node / identity policies nodes)
        if target_node_base.get_node_arn() == resolved_stmt.stmt_parent_arn and (
            # if there is policy name, compare it
            resolved_stmt.policy_name is None
            or resolved_stmt.policy_name == target_node_base.get_node_name()
        ):
            node_base_to_add = target_node_base
        elif resource_node_note.get_node_arn() == resolved_stmt.stmt_parent_arn:
            node_base_to_add = resource_node_note
        else:
            # for each principal node base (For example could be 2 in a line, IAM User & IAM Group):
            # check if the resolved_stmt with the deny condition coming from inline policy or attached iam policy (which doesn't appear as a node in the allowed line nodes)
            for principal_policies_node_base in principal_policies_node_bases:
                if principal_policies_node_base.get_node_arn() == resolved_stmt.stmt_parent_arn:
                    node_base_to_add = principal_policies_node_base
                    break
                else:
                    for attached_policy_arn in principal_policies_node_base.get_attached_policies_arn():
                        if attached_policy_arn == resolved_stmt.stmt_parent_arn:
                            attached_iam_policy = f" ({resolved_stmt.stmt_parent_arn})"
                            node_base_to_add = principal_policies_node_base
                            break
                if node_base_to_add:
                    break

        if node_base_to_add:
            node_base_to_add.add_node_note(
                NodeNote(
                    NodeNoteType.POLICY_STMT_DENY_WITH_CONDITION,
                    f"{stmt_name}{policy_name}{attached_iam_policy} has deny with condition for {service_name} service",
                )
            )


def add_node_notes_from_target_policy_resource_based(
    policy_evaluations_result: PolicyEvaluationsResult,
    service_name: str,
    principal_policies_node_bases: List[PoliciesAndNodeNoteBase],
    target_node_base: NodeNoteBase,
    resource_node_note: NodeNoteBase,
):
    policy_apply_result = policy_evaluations_result.get_policy_apply_result()
    if policy_apply_result:
        _add_node_notes(
            policy_apply_result=policy_apply_result,
            service_name=service_name,
            principal_policies_node_bases=principal_policies_node_bases,
            target_node_base=target_node_base,
            resource_node_note=resource_node_note,
        )
    policy_apply_result_cross_account = policy_evaluations_result.get_cross_account_policy_apply_result()
    if policy_apply_result_cross_account:
        _add_node_notes(
            policy_apply_result=policy_apply_result_cross_account,
            service_name=service_name,
            principal_policies_node_bases=principal_policies_node_bases,
            target_node_base=target_node_base,
            resource_node_note=resource_node_note,
        )


def add_node_notes_from_target_policies_identity_based(
    policy_evaluation_result: PolicyEvaluationResult,
    service_name: str,
    principal_policies_node_bases: List[PoliciesAndNodeNoteBase],
    target_node_base: NodeNoteBase,
    resource_node_note: NodeNoteBase,
):
    policy_apply_result = policy_evaluation_result.get_policy_apply_result()
    if policy_apply_result:
        _add_node_notes(
            policy_apply_result=policy_apply_result,
            service_name=service_name,
            principal_policies_node_bases=principal_policies_node_bases,
            target_node_base=target_node_base,
            resource_node_note=resource_node_note,
        )
