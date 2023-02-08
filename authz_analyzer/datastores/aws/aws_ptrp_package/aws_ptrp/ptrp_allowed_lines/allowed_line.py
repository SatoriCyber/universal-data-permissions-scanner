from dataclasses import dataclass
from logging import Logger
from typing import Dict, Generator, List, Optional, Tuple

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.iam_policies import IAMPolicy
from aws_ptrp.iam.iam_roles import IAMRole, RoleSession
from aws_ptrp.iam.policy.policy_document import PolicyDocument, PolicyDocumentCtx
from aws_ptrp.policy_evaluation import PolicyEvaluation, PolicyEvaluationResult, PolicyEvaluationsResult
from aws_ptrp.ptrp_allowed_lines.allowed_line_node_notes import (
    add_node_notes_from_target_policies_identity_based,
    add_node_notes_from_target_policy_resource_based,
)
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import (
    PathFederatedPrincipalNode,
    PathPolicyNode,
    PathRoleNode,
    PathUserGroupNode,
    PoliciesAndNodeNoteBase,
    PrincipalAndNodeNoteBase,
    PrincipalAndPoliciesNode,
    ResourceNode,
)
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpPathNode
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import ServiceResourceBase
from aws_ptrp.services.assume_role.assume_role_resources import AssumeRoleServiceResourcesResolver
from aws_ptrp.services.assume_role.assume_role_service import AssumeRoleService
from aws_ptrp.services.federated_user.federated_user_resources import (
    FederatedUserPrincipal,
    FederatedUserServiceResourcesResolver,
)
from aws_ptrp.services.federated_user.federated_user_service import FederatedUserService


@dataclass
class PtrpAllowedLine:
    principal_node: PrincipalAndPoliciesNode
    path_user_group_node: Optional[PathUserGroupNode]
    path_federated_nodes: Optional[Tuple[PathPolicyNode, PathFederatedPrincipalNode]]
    path_role_nodes: List[PathRoleNode]
    target_policy_node: PathPolicyNode
    resource_node: ResourceNode

    def is_assuming_roles_allowed(
        self,
        logger: Logger,
        aws_actions: AwsActions,
        account_resources: AwsAccountResources,
        iam_policies: Dict[str, IAMPolicy],
    ) -> bool:
        service_resource_type = AssumeRoleService()
        for yield_res in self.yield_principal_and_its_assumed_role():
            principal: PrincipalAndNodeNoteBase = yield_res[0]
            policies_node_base: List[PoliciesAndNodeNoteBase] = yield_res[1]
            path_role_node: PathRoleNode = yield_res[2]
            principal_policies_ctx: List[PolicyDocumentCtx] = PtrpAllowedLine.get_policies_ctx(
                policies_node_base, iam_policies
            )
            iam_role = path_role_node.get_service_resource()
            assert isinstance(iam_role, IAMRole)

            policy_evaluations_result: PolicyEvaluationsResult = PolicyEvaluation.run_target_policy_resource_based(
                logger=logger,
                aws_actions=aws_actions,
                account_resources=account_resources,
                principal_policies_ctx=principal_policies_ctx,
                target_service_resource=iam_role,
                service_resource_type=service_resource_type,
                identity_principal=principal.get_stmt_principal(),
            )
            add_node_notes_from_target_policy_resource_based(
                policy_evaluations_result=policy_evaluations_result,
                service_name=service_resource_type.get_service_name(),
                principal_policies_node_bases=policies_node_base,
                target_node_base=path_role_node,
                resource_node_note=path_role_node,
            )
            assume_role_service_resolver = policy_evaluations_result.get_target_resolver()

            if (
                assume_role_service_resolver is None
                or isinstance(assume_role_service_resolver, AssumeRoleServiceResourcesResolver) is False
            ):
                return False

            assert isinstance(assume_role_service_resolver, AssumeRoleServiceResourcesResolver)
            if (
                assume_role_service_resolver.is_trusted_principal(  # pylint: disable=E1101:no-member
                    iam_role, principal.get_stmt_principal()
                )
                is False
            ):
                return False

        return True

    def is_assuming_federated_user_allowed(
        self,
        logger: Logger,
        aws_actions: AwsActions,
        account_resources: AwsAccountResources,
        iam_policies: Dict[str, IAMPolicy],
    ) -> bool:
        res = self.get_principal_and_its_assumed_federated_user()
        if res is None:
            return True

        service_resource_type = FederatedUserService()
        principal: PrincipalAndNodeNoteBase = res[0]
        policies_node_base: List[PoliciesAndNodeNoteBase] = res[1]
        target_identity_node: PathPolicyNode = res[2]
        target_identity_policy_ctx = PolicyDocumentCtx(
            policy_document=target_identity_node.get_policy(),
            policy_name=target_identity_node.get_path_name(),
            parent_arn=target_identity_node.get_path_arn(),
        )
        federated_principal_node: PathFederatedPrincipalNode = res[3]
        federated_user_resource: ServiceResourceBase = federated_principal_node.get_service_resource()
        assert isinstance(federated_user_resource, FederatedUserPrincipal)
        principal_policies_ctx: List[PolicyDocumentCtx] = PtrpAllowedLine.get_policies_ctx(
            policies_node_base, iam_policies
        )

        policy_evaluation_result: PolicyEvaluationResult = PolicyEvaluation.run_target_policies_identity_based(
            logger=logger,
            aws_actions=aws_actions,
            account_resources=account_resources,
            target_identity_policies_ctx=[target_identity_policy_ctx],
            principal_policies_ctx=principal_policies_ctx,
            service_resource=federated_user_resource,
            service_resource_type=service_resource_type,
            identity_principal=principal.get_stmt_principal(),
            during_cross_account_checking_flow=True,  # in both single-account/cross-accounts access. iam user must have explicit allow to the GetFederationToken action
        )
        add_node_notes_from_target_policies_identity_based(
            policy_evaluation_result=policy_evaluation_result,
            service_name=service_resource_type.get_service_name(),
            principal_policies_node_bases=policies_node_base,
            target_node_base=target_identity_node,
            resource_node_note=federated_principal_node,
        )
        federated_user_service_resources_resolver = policy_evaluation_result.get_target_resolver()

        if (
            federated_user_service_resources_resolver is None
            or isinstance(federated_user_service_resources_resolver, FederatedUserServiceResourcesResolver) is False
        ):
            return False

        assert isinstance(federated_user_service_resources_resolver, FederatedUserServiceResourcesResolver)
        if (
            federated_user_service_resources_resolver.is_principal_allowed_to_assume_federated_user(  # pylint: disable=E1101:no-member
                federated_user_resource, principal.get_stmt_principal()
            )
            is False
        ):
            return False
        return True

    def get_ptrp_path_nodes_to_report(self) -> List[AwsPtrpPathNode]:
        path: List[AwsPtrpPathNode] = []
        if self.path_user_group_node:
            path.append(self.path_user_group_node.get_ptrp_path_node())

        # path can't contains both federated nodes & role nodes
        if self.path_federated_nodes:
            path.append(self.path_federated_nodes[0].get_ptrp_path_node())
            path.append(self.path_federated_nodes[1].get_ptrp_path_node())
        else:
            for path_role_node in self.path_role_nodes:
                path.append(path_role_node.get_ptrp_path_node())

        path.append(self.target_policy_node.get_ptrp_path_node())
        return path

    def get_principal_makes_the_request_to_resource(self) -> PrincipalAndNodeNoteBase:
        if self.path_role_nodes:
            return self.path_role_nodes[-1]
        elif self.path_federated_nodes:
            return self.path_federated_nodes[1]
        else:
            return self.principal_node

    def yield_principal_and_its_assumed_role(
        self,
    ) -> Generator[Tuple[PrincipalAndNodeNoteBase, List[PoliciesAndNodeNoteBase], PathRoleNode], None, None]:
        '''yield tuple of every assumed role in the line. Each tuple is the principal, the relevant list of PoliciesNodeBase, and role which its assuming'''
        curr_principal: PrincipalAndNodeNoteBase = self.principal_node
        policies_node_base: List[PoliciesAndNodeNoteBase] = [self.principal_node]
        if self.path_user_group_node:
            policies_node_base.append(self.path_user_group_node)

        for path_role_node in self.path_role_nodes:
            if isinstance(path_role_node.base, RoleSession):
                # current principal is the role and the path_role_node is the role session (from this role), skipping
                assert curr_principal.get_stmt_principal() == path_role_node.base.iam_role.get_stmt_principal()
                curr_principal = path_role_node
                continue

            yield curr_principal, policies_node_base, path_role_node
            policies_node_base = [path_role_node]
            curr_principal = path_role_node

    def get_principal_and_its_assumed_federated_user(
        self,
    ) -> Optional[
        Tuple[PrincipalAndNodeNoteBase, List[PoliciesAndNodeNoteBase], PathPolicyNode, PathFederatedPrincipalNode]
    ]:
        '''get the assumed federated user in the line. Return tuple is the principal, the relevant list of PoliciesNodeBase,
        the policy with the GetFederationToken to the federated-user resources, and the actual actual federated-user resolved resource
        '''
        if self.path_federated_nodes:
            policies_node_base: List[PoliciesAndNodeNoteBase] = [self.principal_node]
            if self.path_user_group_node:
                policies_node_base.append(self.path_user_group_node)
            return (
                self.principal_node,
                policies_node_base,
                self.path_federated_nodes[0],
                self.path_federated_nodes[1],
            )
        return None

    @staticmethod
    def get_policies_ctx(
        policies_node_bases: List[PoliciesAndNodeNoteBase], iam_policies: Dict[str, IAMPolicy]
    ) -> List[PolicyDocumentCtx]:
        policies_ctx: List[PolicyDocumentCtx] = []
        # Extract all principal policies (inline & attached)
        for policies_node_base in policies_node_bases:
            policies_ctx.extend(
                list(
                    map(
                        lambda arn: iam_policies[arn].to_policy_document_ctx(),
                        policies_node_base.get_attached_policies_arn(),
                    )
                )
            )

            inline_policies_and_names: List[
                Tuple[PolicyDocument, str]
            ] = policies_node_base.get_inline_policies_and_names()
            policies_ctx.extend(
                [
                    PolicyDocumentCtx(
                        policy_document=policy_and_name[0],
                        policy_name=policy_and_name[1],
                        parent_arn=policies_node_base.get_node_arn(),
                    )
                    for policy_and_name in inline_policies_and_names
                ]
            )
        return policies_ctx

    def get_principal_policies_bases(self) -> List[PoliciesAndNodeNoteBase]:
        if self.path_role_nodes:
            return [self.path_role_nodes[-1]]
        else:
            ret: List[PoliciesAndNodeNoteBase] = [self.principal_node]
            if self.path_user_group_node:
                ret.append(self.path_user_group_node)
            return ret
