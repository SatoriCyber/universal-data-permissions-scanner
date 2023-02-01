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
    note_prefix: str,
    principal_node_note: NodeNoteBase,
    principal_policies_node_notes: List[PoliciesAndNodeNoteBase],
    resource_node_note: Optional[NodeNoteBase],
):
    for resolved_stmt in policy_apply_result.explicit_deny_result.yield_resolved_stmts_from_identity_policies(
        MethodOnStmtActionsType.DIFFERENCE, MethodOnStmtActionsResultType.IGNORE_METHOD_DIFFERENCE_CONDITION_EXISTS
    ):
        for principal_policies_node_note in principal_policies_node_notes:
            if (
                principal_policies_node_note.get_node_arn() == resolved_stmt.stmt_parent_arn
                and principal_policies_node_note.get_node_name() == resolved_stmt.policy_name
            ):
                principal_node_note.add_node_note(
                    NodeNote(
                        NodeNoteType.POLICY_STMT_DENY_WITH_CONDITION,
                        f"{note_prefix} policy has deny with condition. Element(Arn: {resolved_stmt.stmt_parent_arn}, Name: {resolved_stmt.policy_name}",
                    )
                )

    if resource_node_note:
        for resolved_stmt in policy_apply_result.explicit_deny_result.yield_resolved_stmts_from_resource_policy(
            MethodOnStmtActionsType.DIFFERENCE,
            MethodOnStmtActionsResultType.IGNORE_METHOD_DIFFERENCE_CONDITION_EXISTS,
        ):
            # for resource node, the resolved_stmt policy_name is None, no need to compare it
            if resource_node_note.get_node_arn() == resolved_stmt.stmt_parent_arn:
                resource_node_note.add_node_note(
                    NodeNote(
                        NodeNoteType.POLICY_STMT_DENY_WITH_CONDITION,
                        f"{note_prefix} policy has deny with condition. Element(Arn: {resolved_stmt.stmt_parent_arn})",
                    )
                )


def add_node_notes_from_target_policy_resource_based(
    policy_evaluations_result: PolicyEvaluationsResult,
    note_prefix: str,
    principal_node_note: NodeNoteBase,
    principal_policies_node_notes: List[PoliciesAndNodeNoteBase],
    resource_node_note: NodeNoteBase,
):
    policy_apply_result = policy_evaluations_result.get_policy_apply_result()
    if policy_apply_result:
        _add_node_notes(
            policy_apply_result,
            note_prefix,
            principal_node_note,
            principal_policies_node_notes,
            resource_node_note,
        )
    policy_apply_result_cross_account = policy_evaluations_result.get_cross_account_policy_apply_result()
    if policy_apply_result_cross_account:
        _add_node_notes(
            policy_apply_result_cross_account,
            f"{note_prefix} in cross-accounts access",
            principal_node_note,
            principal_policies_node_notes,
            resource_node_note,
        )


def add_node_notes_from_target_policies_identity_based(
    policy_evaluation_result: PolicyEvaluationResult,
    note_prefix: str,
    principal_node_note: NodeNoteBase,
    principal_policies_node_notes: List[PoliciesAndNodeNoteBase],
    resource_node_note: Optional[NodeNoteBase],
):
    policy_apply_result = policy_evaluation_result.get_policy_apply_result()
    if policy_apply_result:
        _add_node_notes(
            policy_apply_result, note_prefix, principal_node_note, principal_policies_node_notes, resource_node_note
        )
