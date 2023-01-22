from dataclasses import dataclass
from logging import Logger
from typing import Dict, Generator, List, Optional, Tuple

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.iam_entities import IAMRole
from aws_ptrp.iam.iam_policies import IAMPolicy
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.policy_evaluation import PolicyEvaluation
from aws_ptrp.principals import Principal
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import (
    PathFederatedPrincipalNode,
    PathFederatedPrincipalNodeBase,
    PathPolicyNode,
    PathRoleNode,
    PathUserGroupNode,
    PoliciesNodeBase,
    PrincipalAndPoliciesNodeBase,
    PrincipalNodeBase,
    ResourceNode,
)
from aws_ptrp.ptrp_models.ptrp_model import AwsPrincipal, AwsPtrpPathNode, AwsPtrpResource
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import ServiceResourceBase, ServiceResourcesResolverBase
from aws_ptrp.services.assume_role.assume_role_resources import AssumeRoleServiceResourcesResolver
from aws_ptrp.services.assume_role.assume_role_service import AssumeRoleService
from aws_ptrp.services.federated_user.federated_user_resources import (
    FederatedUserPrincipal,
    FederatedUserServiceResourcesResolver,
)
from aws_ptrp.services.federated_user.federated_user_service import FederatedUserService


@dataclass
class PtrpAllowedLine:
    principal_node: PrincipalAndPoliciesNodeBase
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
        for yield_res in self.yield_principal_and_its_assumed_role():
            principal: PrincipalNodeBase = yield_res[0]
            policies_node_base: List[PoliciesNodeBase] = yield_res[1]
            assumed_role: PathRoleNode = yield_res[2]
            identity_policies = PtrpAllowedLine.get_principal_policies(policies_node_base, iam_policies)
            iam_role = assumed_role.get_service_resource()
            assert isinstance(iam_role, IAMRole)

            assume_role_service_resolver: Optional[
                ServiceResourcesResolverBase
            ] = PolicyEvaluation.run_target_policy_resource_based(
                logger=logger,
                aws_actions=aws_actions,
                account_resources=account_resources,
                identity_policies=identity_policies,
                target_service_resource=iam_role,
                service_resource_type=AssumeRoleService(),
                identity_principal=principal.get_stmt_principal(),
            )
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

        principal: PrincipalNodeBase = res[0]
        policies_node_base: List[PoliciesNodeBase] = res[1]
        target_identity_policy: PolicyDocument = res[2].get_policy()
        federated_user_resource: ServiceResourceBase = res[3].get_service_resource()
        assert isinstance(federated_user_resource, FederatedUserPrincipal)
        identity_policies = PtrpAllowedLine.get_principal_policies(policies_node_base, iam_policies)

        federated_user_service_resources_resolver: Optional[
            ServiceResourcesResolverBase
        ] = PolicyEvaluation.run_target_policies_identity_based(
            logger=logger,
            aws_actions=aws_actions,
            account_resources=account_resources,
            target_identity_policies=[target_identity_policy],
            identity_policies=identity_policies,
            service_resource=federated_user_resource,
            service_resource_type=FederatedUserService(),
            identity_principal=principal.get_stmt_principal(),
            during_cross_account_checking_flow=True,  # in both single-account/cross-accounts access. iam user must have explicit allow to the GetFederationToken action
        )
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

    def get_ptrp_resource_to_report(self) -> AwsPtrpResource:
        return AwsPtrpResource(
            name=self.resource_node.base.get_resource_name(), type=self.resource_node.base.get_ptrp_resource_type()
        )

    def get_principal_to_report(self) -> AwsPrincipal:
        principal_to_report: Principal = self.principal_node.get_stmt_principal()
        return AwsPrincipal(
            arn=principal_to_report.get_arn(),
            type=principal_to_report.principal_type,
            name=principal_to_report.get_name(),
        )

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

    def get_principal_makes_the_request_to_resource(self) -> Principal:
        if self.path_role_nodes:
            return self.path_role_nodes[-1].base.get_stmt_principal()
        elif self.path_federated_nodes:
            return self.path_federated_nodes[1].get_stmt_principal()
        else:
            return self.principal_node.get_stmt_principal()

    def yield_principal_and_its_assumed_role(
        self,
    ) -> Generator[Tuple[PrincipalNodeBase, List[PoliciesNodeBase], PathRoleNode], None, None]:
        '''yield tuple of every assumed role in the line. Each tuple is the principal, the relevant list of PoliciesNodeBase, and role which its assuming'''
        curr_principal: PrincipalNodeBase = self.principal_node
        policies_node_base: List[PoliciesNodeBase] = [self.principal_node]
        if self.path_user_group_node:
            policies_node_base.append(self.path_user_group_node.base)

        for path_role_node in self.path_role_nodes:
            yield curr_principal, policies_node_base, path_role_node
            policies_node_base = [path_role_node.base]
            curr_principal = path_role_node

    def get_principal_and_its_assumed_federated_user(
        self,
    ) -> Optional[Tuple[PrincipalNodeBase, List[PoliciesNodeBase], PathPolicyNode, PathFederatedPrincipalNodeBase]]:
        '''get the assumed federated user in the line. Return tuple is the principal, the relevant list of PoliciesNodeBase,
        the policy with the GetFederationToken to the federated-user resources, and the actual actual federated-user resolved resource'''
        if self.path_federated_nodes:
            policies_node_base: List[PoliciesNodeBase] = [self.principal_node]
            if self.path_user_group_node:
                policies_node_base.append(self.path_user_group_node.base)
            return (
                self.principal_node,
                policies_node_base,
                self.path_federated_nodes[0],
                self.path_federated_nodes[1].base,
            )
        return None

    @staticmethod
    def get_principal_policies(
        principal_policies_bases: List[PoliciesNodeBase], iam_policies: Dict[str, IAMPolicy]
    ) -> List[PolicyDocument]:
        principal_policies: List[PolicyDocument] = []
        # Extract all principal policies (inline & attached)
        for principal_policies_base in principal_policies_bases:
            principal_policies.extend(
                list(
                    map(
                        lambda arn: iam_policies[arn].policy_document,
                        principal_policies_base.get_attached_policies_arn(),
                    )
                )
            )
            inline_policies_and_names: List[
                Tuple[PolicyDocument, str]
            ] = principal_policies_base.get_inline_policies_and_names()
            principal_policies.extend(
                list(
                    map(
                        lambda policy_and_name: policy_and_name[0],
                        inline_policies_and_names,
                    )
                )
            )
        return principal_policies

    def get_principal_policies_bases(self) -> List[PoliciesNodeBase]:
        if self.path_role_nodes:
            return [self.path_role_nodes[-1].base]
        else:
            ret: List[PoliciesNodeBase] = [self.principal_node]
            if self.path_user_group_node:
                ret.append(self.path_user_group_node.base)
            return ret
