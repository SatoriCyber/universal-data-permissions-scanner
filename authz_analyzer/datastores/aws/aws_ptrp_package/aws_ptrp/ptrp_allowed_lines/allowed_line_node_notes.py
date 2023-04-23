from dataclasses import dataclass, field
from typing import Dict, List, Optional

from aws_ptrp.policy_evaluation import PolicyEvaluationApplyResult, PolicyEvaluationResult, PolicyEvaluationsResult
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import NodeBase, NodeNote, NodeNotesGetter, PoliciesNodeBase
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpNodeNote
from aws_ptrp.services import MethodOnStmtActionsResultType, MethodOnStmtActionsType


@dataclass
class NodeNotes:
    node_notes: List[NodeNote] = field(default_factory=list)

    def extend(self, other: 'NodeNotes'):
        self.node_notes.extend(other.node_notes)

    def add_node_note(self, node_note: NodeNote):
        self.node_notes.append(node_note)

    def get_node_notes(self) -> List[NodeNote]:
        return self.node_notes

    def get_aws_ptrp_node_notes(self) -> List[AwsPtrpNodeNote]:
        return [node_note.to_ptrp_node_note() for node_note in self.node_notes]


@dataclass
class NodesNotes(NodeNotesGetter):
    nodes_notes: Dict[NodeBase, NodeNotes] = field(default_factory=dict)

    def extend(self, other: 'NodesNotes'):
        for other_node_base, other_node_notes in other.nodes_notes.items():
            node_notes: Optional[NodeNotes] = self.nodes_notes.get(other_node_base)
            if node_notes:
                node_notes.extend(other_node_notes)
            else:
                self.nodes_notes[other_node_base] = other_node_notes

    # NodeNotesGetter
    def get_node_notes(self, node_base: NodeBase) -> List[NodeNote]:
        node_notes = self.nodes_notes.get(node_base)
        if node_notes:
            return node_notes.get_node_notes()
        return []

    def get_aws_ptrp_node_notes(self, node_base: NodeBase) -> List[AwsPtrpNodeNote]:
        node_notes = self.nodes_notes.get(node_base)
        if node_notes:
            ret = node_notes.get_aws_ptrp_node_notes()
            ret.sort()
            return ret
        return []


def _update_nodes_notes(
    nodes_notes: NodesNotes,
    policy_apply_result: PolicyEvaluationApplyResult,
    service_name: str,
    principal_policies_node_base: PoliciesNodeBase,
    target_node_base: NodeBase,
    resource_node_note: NodeBase,
):
    # For each resolved_stmt in the policy evaluation result, explicit deny result: check if there are stmt with Deny + condition
    for (
        resolved_stmt,
        method_on_stmt_actions_result_type,
    ) in policy_apply_result.explicit_deny_result.yield_resolved_stmts(
        MethodOnStmtActionsType.DIFFERENCE,
        list(
            [
                MethodOnStmtActionsResultType.IGNORE_METHOD_DIFFERENCE_CONDITION_EXISTS,
                MethodOnStmtActionsResultType.IGNORE_METHOD_DIFFERENCE_WITH_S3_NOT_RESOURCE_OBJECT_REGEX,
            ]
        ),
    ):
        # build the node note params
        stmt_name = f"statement '{resolved_stmt.stmt_name}' in " if resolved_stmt.stmt_name else ''
        policy_name = (
            f"policy '{resolved_stmt.policy_name}'"
            if resolved_stmt.policy_name
            else f"policy of {resolved_stmt.stmt_parent_arn}"
        )
        attached_to_other_node_arn = ""
        node_base_to_add: Optional[NodeBase] = None

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
            # check if the resolved_stmt coming from inline policy or attached iam policy (which doesn't appear as a node in the allowed line nodes)
            for inline_policy_ctx in principal_policies_node_base.get_inline_policies_ctx():
                if inline_policy_ctx.parent_arn == resolved_stmt.stmt_parent_arn:
                    node_base_to_add = principal_policies_node_base
                    # if the arn of the node is not the same as the inline policy arn (can happen for iam user that attached to iam group which has inline policy)
                    if principal_policies_node_base.get_node_arn() != inline_policy_ctx.parent_arn:
                        attached_to_other_node_arn = f" ({resolved_stmt.stmt_parent_arn})"
                    break
            if node_base_to_add is None:
                for attached_policy_arn in principal_policies_node_base.get_attached_policies_arn():
                    if attached_policy_arn == resolved_stmt.stmt_parent_arn:
                        attached_to_other_node_arn = f" ({resolved_stmt.stmt_parent_arn})"
                        node_base_to_add = principal_policies_node_base
                        break

        if node_base_to_add:
            node_notes = nodes_notes.nodes_notes.setdefault(node_base_to_add, NodeNotes())
            note = NodeNote.from_stmt_info_and_action_stmt_result_type(
                stmt_name, policy_name, attached_to_other_node_arn, service_name, method_on_stmt_actions_result_type
            )
            if note:
                node_notes.add_node_note(note)


def get_nodes_notes_from_target_policy_resource_based(
    policy_evaluations_result: PolicyEvaluationsResult,
    service_name: str,
    principal_policies_node_base: PoliciesNodeBase,
    target_node_base: NodeBase,
    resource_node_note: NodeBase,
) -> NodesNotes:
    nodes_notes = NodesNotes()
    policy_apply_result = policy_evaluations_result.get_policy_apply_result()
    if policy_apply_result:
        _update_nodes_notes(
            nodes_notes=nodes_notes,
            policy_apply_result=policy_apply_result,
            service_name=service_name,
            principal_policies_node_base=principal_policies_node_base,
            target_node_base=target_node_base,
            resource_node_note=resource_node_note,
        )
    policy_apply_result_cross_account = policy_evaluations_result.get_cross_account_policy_apply_result()
    if policy_apply_result_cross_account:
        _update_nodes_notes(
            nodes_notes=nodes_notes,
            policy_apply_result=policy_apply_result_cross_account,
            service_name=service_name,
            principal_policies_node_base=principal_policies_node_base,
            target_node_base=target_node_base,
            resource_node_note=resource_node_note,
        )
    return nodes_notes


def get_nodes_notes_from_target_policies_identity_based(
    policy_evaluation_result: PolicyEvaluationResult,
    service_name: str,
    principal_policies_node_base: PoliciesNodeBase,
    target_node_base: NodeBase,
    resource_node_note: NodeBase,
) -> NodesNotes:
    policy_apply_result = policy_evaluation_result.get_policy_apply_result()
    nodes_notes = NodesNotes()
    if policy_apply_result:
        _update_nodes_notes(
            nodes_notes=nodes_notes,
            policy_apply_result=policy_apply_result,
            service_name=service_name,
            principal_policies_node_base=principal_policies_node_base,
            target_node_base=target_node_base,
            resource_node_note=resource_node_note,
        )
    return nodes_notes


def get_nodes_notes_from_identity_center_user(
    target_node_base: NodeBase,
    identity_center_instance_arn: str,
    identity_center_account_id: str,
    identity_center_region: str,
) -> NodesNotes:
    nodes_notes = NodesNotes()
    note = NodeNote.from_user_and_identity_center_instance_info(
        target_node_base.get_node_name(),
        identity_center_instance_arn,
        identity_center_account_id,
        identity_center_region,
    )
    nodes_notes.nodes_notes.setdefault(target_node_base, NodeNotes()).add_node_note(note)
    return nodes_notes
