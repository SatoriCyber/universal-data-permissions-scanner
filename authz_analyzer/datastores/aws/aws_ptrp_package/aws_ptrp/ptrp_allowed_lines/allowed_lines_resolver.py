from dataclasses import dataclass, field
from logging import Logger
from typing import Dict, Generator, List, Optional, Set, Tuple, Union

import networkx as nx
from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.iam.iam_roles import IAMRole, RoleSession
from aws_ptrp.iam.iam_users import IAMUser
from aws_ptrp.iam.policy.policy_document import Effect, PolicyDocument, PolicyDocumentCtx
from aws_ptrp.iam.policy.policy_document_resolver import (
    get_identity_based_resolver,
    get_resource_based_resolver,
    get_role_trust_resolver,
)
from aws_ptrp.iam_identity_center.iam_identity_center_entities import IamIdentityCenterEntities
from aws_ptrp.principals import Principal, PrincipalBase
from aws_ptrp.principals.aws_principals import AwsPrincipals
from aws_ptrp.principals.no_entity_principal import NoEntityPrincipal
from aws_ptrp.ptrp_allowed_lines.allowed_line import PtrpAllowedLine
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import (
    PathFederatedPrincipalNode,
    PathFederatedPrincipalNodeBase,
    PathNodeBase,
    PathPermissionSetNode,
    PathPermissionSetNodeBase,
    PathPolicyNode,
    PathRoleNode,
    PathRoleNodeBase,
    PathUserGroupNode,
    PathUserGroupNodeBase,
    PoliciesNodeBase,
    PrincipalAndPoliciesNode,
    PrincipalAndPoliciesNodeBase,
    PrincipalNodeBase,
    ResourceNode,
    ResourceNodeBase,
)
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpPathNodeType
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import ServiceResourceBase, ServiceResourcesResolverBase, ServiceResourceType
from aws_ptrp.services.assume_role.assume_role_resources import AssumeRoleServiceResourcesResolver
from aws_ptrp.services.federated_user.federated_user_resources import FederatedUserPrincipal, FederatedUserResource
from aws_ptrp.services.federated_user.federated_user_service import FederatedUserService

START_NODE = "START_NODE"
END_NODE = "END_NODE"


@dataclass
class PtrpAllowedLines:
    graph: nx.DiGraph
    iam_identity_center_exists: bool

    def yield_principal_to_resource_lines(
        self,
    ) -> Generator[PtrpAllowedLine, None, None,]:
        for graph_path in nx.all_simple_paths(self.graph, source=START_NODE, target=END_NODE):
            graph_path = graph_path[1:-1]  # without the START_NODE, END_NODE
            if len(graph_path) < 3:
                raise Exception(f"Got invalid simple path in graph, expecting at least 3 nodes: {graph_path}")
            if not isinstance(graph_path[0], PrincipalAndPoliciesNode):
                raise Exception(
                    f"Got invalid simple path in graph, first node is not impl PrincipalAndPoliciesNode: {graph_path}"
                )
            principal_node: PrincipalAndPoliciesNode = graph_path[0]
            # If we have an IAM Identity Center, we don't want to show the AWS SSO SAML providers principals in the permission lines
            if self.iam_identity_center_exists and principal_node.get_stmt_principal().is_aws_sso_saml_session():
                continue

            if isinstance(graph_path[1], PathUserGroupNode):
                path_user_group_node: Optional[PathUserGroupNode] = graph_path[1]
                start_index_path_role_identity_nodes = 2
            else:
                path_user_group_node = None
                start_index_path_role_identity_nodes = 1

            if isinstance(graph_path[start_index_path_role_identity_nodes], PathPolicyNode) and isinstance(
                graph_path[start_index_path_role_identity_nodes + 1], PathFederatedPrincipalNode
            ):
                path_federated_policy_node: PathPolicyNode = graph_path[start_index_path_role_identity_nodes]
                path_federated_principal_node: PathFederatedPrincipalNode = graph_path[
                    start_index_path_role_identity_nodes + 1
                ]

                path_federated_nodes: Optional[Tuple[PathPolicyNode, PathFederatedPrincipalNode]] = (
                    path_federated_policy_node,
                    path_federated_principal_node,
                )
                start_index_path_role_identity_nodes = start_index_path_role_identity_nodes + 2
            else:
                path_federated_nodes = None

            # If there is a path_permission_set_node, it will come before the role nodes
            if isinstance(graph_path[start_index_path_role_identity_nodes], PathPermissionSetNode):
                path_permission_set_node: Optional[PathPermissionSetNode] = graph_path[
                    start_index_path_role_identity_nodes
                ]
                start_index_path_role_identity_nodes = start_index_path_role_identity_nodes + 1
            else:
                path_permission_set_node = None

            if len(graph_path) - 2 < start_index_path_role_identity_nodes:
                raise Exception(f"Got invalid simple path in graph, (not enough nodes): {graph_path}")

            all_path_role_identity_nodes_valid = all(
                isinstance(path_element, PathRoleNode)
                for path_element in graph_path[start_index_path_role_identity_nodes:-2]
            )
            if not all_path_role_identity_nodes_valid:
                raise Exception(
                    f"Got invalid simple path in graph, not all nodes are impl PathRoleNode: {graph_path[start_index_path_role_identity_nodes:-2]}"
                )
            path_role_identity_nodes: List[PathRoleNode] = graph_path[start_index_path_role_identity_nodes:-2]

            # path must not be with non-empty list of roles path_federated_nodes
            if path_role_identity_nodes and path_federated_nodes:
                raise Exception(
                    f"Got invalid simple path in graph, both roles and federated nodes exists: {path_role_identity_nodes}, {path_federated_nodes}"
                )

            if not isinstance(graph_path[-2], PathPolicyNode):
                raise Exception(
                    f"Got invalid simple path in graph, last_node-1 is not impl PathPolicyNode: {graph_path[-2]}"
                )
            target_policy_node: PathPolicyNode = graph_path[-2]

            if not isinstance(graph_path[-1], ResourceNode):
                raise Exception(
                    f"Got invalid simple path in graph, last node is not impl ResourceNode: {graph_path[-1]}"
                )
            resource_node: ResourceNode = graph_path[-1]

            yield PtrpAllowedLine(
                principal_node=principal_node,
                path_user_group_node=path_user_group_node,
                path_federated_nodes=path_federated_nodes,
                path_permission_set_node=path_permission_set_node,
                path_role_nodes=path_role_identity_nodes,
                target_policy_node=target_policy_node,
                resource_node=resource_node,
            )


@dataclass
class PtrpAllowedLinesBuilder:
    logger: Logger
    iam_entities: IAMEntities
    iam_identity_center_entities: Optional[IamIdentityCenterEntities]
    aws_actions: AwsActions
    aws_principals: AwsPrincipals
    account_resources: AwsAccountResources
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)

    def _get_resolved_principal_node_base(
        self,
        parent_stmt_arn: str,
        stmt_principal_base: PrincipalBase,
    ) -> PrincipalNodeBase:
        if isinstance(stmt_principal_base, IAMRole):
            assert isinstance(stmt_principal_base, PathRoleNodeBase)
            return PathRoleNode(base=stmt_principal_base)

        elif isinstance(stmt_principal_base, RoleSession):
            # need to connect the role session node to its matched iam role
            assert isinstance(stmt_principal_base, PathRoleNodeBase)
            path_iam_role_node = PathRoleNode(base=stmt_principal_base.iam_role)
            path_role_session_node = PathRoleNode(base=stmt_principal_base)
            self.graph.add_edge(path_iam_role_node, path_role_session_node)
            return path_role_session_node

        elif isinstance(stmt_principal_base, IAMUser):
            assert isinstance(stmt_principal_base, PrincipalAndPoliciesNodeBase)
            attached_iam_groups = self.iam_entities.get_attached_iam_groups_for_iam_user(stmt_principal_base)
            additional_policies_bases: List[PoliciesNodeBase] = [
                attached_iam_group
                for attached_iam_group in attached_iam_groups
                if isinstance(attached_iam_group, PoliciesNodeBase)
            ]
            principal_iam_user_node = PrincipalAndPoliciesNode(
                base=stmt_principal_base, additional_policies_bases=additional_policies_bases
            )
            self.graph.add_edge(START_NODE, principal_iam_user_node)
            return principal_iam_user_node

        elif isinstance(stmt_principal_base, FederatedUserPrincipal):
            assert isinstance(stmt_principal_base, PathFederatedPrincipalNodeBase)
            federated_user_node = PathFederatedPrincipalNode(base=stmt_principal_base)
            return federated_user_node

        elif isinstance(stmt_principal_base, NoEntityPrincipal):
            assert isinstance(stmt_principal_base, PrincipalAndPoliciesNodeBase)
            no_entity_principal_node = PrincipalAndPoliciesNode(base=stmt_principal_base)
            self.graph.add_edge(START_NODE, no_entity_principal_node)
            return no_entity_principal_node
        else:
            raise Exception(
                f"Unable to create principal node base. In policy of {parent_stmt_arn}, unknown stmt principal: {stmt_principal_base}, type: {type(stmt_principal_base)}"
            )

    def _yield_resolved_service_resources_for_identity_based_policy(
        self,
        identity_principal: Principal,
        policy_document_ctx: PolicyDocumentCtx,
    ) -> Generator[Tuple[ServiceResourceType, ServiceResourceBase], None, None,]:
        service_resources_resolver: Optional[
            Dict[ServiceResourceType, ServiceResourcesResolverBase]
        ] = get_identity_based_resolver(
            logger=self.logger,
            policy_documents_ctx=[policy_document_ctx],
            identity_principal=identity_principal,
            effect=Effect.Allow,
            aws_actions=self.aws_actions,
            aws_principals=self.aws_principals,
            account_resources=self.account_resources,
        )

        if service_resources_resolver:
            for service_type, service_resource_resolver in service_resources_resolver.items():
                for service_resource in service_resource_resolver.yield_resolved_resources(identity_principal):
                    self.logger.debug(
                        "For %s, got resolved resource %s in: %s: %s",
                        identity_principal,
                        service_resource,
                        policy_document_ctx.parent_arn,
                        policy_document_ctx.policy_name,
                    )
                    yield service_type, service_resource

    def _connect_path_policy_node_with_resolved_service_resource(
        self,
        principal_base: PrincipalBase,
        path_policy_node: PathPolicyNode,
        service_resource_type: ServiceResourceType,
        service_resource: ServiceResourceBase,
    ):
        if isinstance(service_resource, ResourceNodeBase):
            resource_node = ResourceNode(base=service_resource, service_resource_type=service_resource_type)
            self.graph.add_edge(path_policy_node, resource_node)
        elif (
            isinstance(principal_base, IAMUser)
            and path_policy_node.is_resource_based_policy is False
            and isinstance(service_resource_type, FederatedUserService)
            and isinstance(service_resource, FederatedUserResource)
        ):
            # special handling for federated user
            # connect the path policy node to the federated principal node
            # add the federated user to the iam_user (for resolving principals in the resource based policy)
            federated_user_principal = FederatedUserPrincipal(
                federated_resource=service_resource, parent_iam_user_arn=principal_base.arn
            )
            principal_base.add_federated_user_principal(federated_user_principal)
            assert isinstance(federated_user_principal, PathFederatedPrincipalNodeBase)
            federated_principal_node = PathFederatedPrincipalNode(base=federated_user_principal)
            self.logger.debug("connecting %s -> %s", path_policy_node, federated_principal_node)
            self.graph.add_edge(path_policy_node, federated_principal_node)

    def _insert_attached_policies_and_inline_policies(
        self,
        node_connect_to_policy: Union[PrincipalNodeBase, PathNodeBase],
        attached_policies_arn: List[str],
        inline_policies_ctx: List[PolicyDocumentCtx],
        principal_base_for_resolver: PrincipalBase,
    ):
        for attached_policy_arn in attached_policies_arn:
            iam_policy = self.iam_entities.get_iam_policy(attached_policy_arn)
            iam_policy_document_ctx = iam_policy.to_policy_document_ctx()
            for service_type, service_resource in self._yield_resolved_service_resources_for_identity_based_policy(
                identity_principal=principal_base_for_resolver.get_principal(),
                policy_document_ctx=iam_policy_document_ctx,
            ):
                path_policy_node = PathPolicyNode(
                    path_element_type=AwsPtrpPathNodeType.IAM_POLICY,
                    policy_document_ctx=iam_policy_document_ctx,
                    is_resource_based_policy=False,
                )
                self.graph.add_edge(node_connect_to_policy, path_policy_node)
                self._connect_path_policy_node_with_resolved_service_resource(
                    principal_base=principal_base_for_resolver,
                    path_policy_node=path_policy_node,
                    service_resource_type=service_type,
                    service_resource=service_resource,
                )
        for inline_policy_ctx in inline_policies_ctx:
            for service_type, service_resource in self._yield_resolved_service_resources_for_identity_based_policy(
                identity_principal=principal_base_for_resolver.get_principal(),
                policy_document_ctx=inline_policy_ctx,
            ):
                path_policy_node = PathPolicyNode(
                    path_element_type=AwsPtrpPathNodeType.IAM_INLINE_POLICY,
                    policy_document_ctx=inline_policy_ctx,
                    is_resource_based_policy=False,
                )
                self.graph.add_edge(node_connect_to_policy, path_policy_node)
                self._connect_path_policy_node_with_resolved_service_resource(
                    principal_base=principal_base_for_resolver,
                    path_policy_node=path_policy_node,
                    service_resource_type=service_type,
                    service_resource=service_resource,
                )

    def _insert_iam_roles_and_trusted_entities(self):
        for iam_role in self.iam_entities.yield_iam_roles():
            # Check the role's trusted entities
            role_trust_service_principal_resolver: Optional[
                AssumeRoleServiceResourcesResolver
            ] = get_role_trust_resolver(
                logger=self.logger,
                role_trust_policy=iam_role.assume_role_policy_document,
                iam_role_arn=iam_role.arn,
                iam_role_aws_account_id=iam_role.get_resource_account_id(),
                effect=Effect.Allow,
                aws_actions=self.aws_actions,
                aws_principals=self.aws_principals,
                account_resources=self.account_resources,
            )

            if role_trust_service_principal_resolver is None:
                continue

            assert isinstance(iam_role, PathRoleNodeBase)
            path_role_node = PathRoleNode(base=iam_role)
            self._insert_attached_policies_and_inline_policies(
                node_connect_to_policy=path_role_node,
                attached_policies_arn=iam_role.get_attached_policies_arn(),
                inline_policies_ctx=iam_role.get_inline_policies_ctx(),
                principal_base_for_resolver=iam_role,
            )

            for trusted_principal_to_resolve in role_trust_service_principal_resolver.yield_trusted_principals(
                iam_role
            ):
                self.logger.debug(
                    "Got role name %s with resolved trusted principal %s",
                    iam_role.role_name,
                    trusted_principal_to_resolve,
                )
                resolved_principal_node = self._get_resolved_principal_node_base(
                    iam_role.arn, trusted_principal_to_resolve
                )
                assert isinstance(resolved_principal_node, PrincipalNodeBase)
                self.logger.debug("connecting %s -> %s", resolved_principal_node, path_role_node)
                self.graph.add_edge(resolved_principal_node, path_role_node)

    def _insert_resources(self):
        for service_resources_type, service_resources in self.account_resources.account_resources.items():
            for service_resource in service_resources:
                if not isinstance(service_resource, ResourceNodeBase):
                    continue
                resource_node = ResourceNode(base=service_resource, service_resource_type=service_resources_type)
                self.graph.add_edge(resource_node, END_NODE)

                service_resource_policy: Optional[PolicyDocument] = service_resource.get_resource_policy()
                if service_resource_policy is None:
                    continue

                service_resources_resolver: Optional[ServiceResourcesResolverBase] = get_resource_based_resolver(
                    logger=self.logger,
                    policy_document=service_resource_policy,
                    service_resource_type=service_resources_type,
                    resource_arn=service_resource.get_resource_arn(),
                    resource_aws_account_id=service_resource.get_resource_account_id(),
                    effect=Effect.Allow,
                    aws_actions=self.aws_actions,
                    aws_principals=self.aws_principals,
                    account_resources=self.account_resources,
                )
                if service_resources_resolver is None:
                    continue

                policy_document_ctx = PolicyDocumentCtx(
                    policy_document=service_resource_policy,
                    policy_name=service_resource.get_resource_name(),
                    parent_arn=service_resource.get_resource_arn(),
                    parent_aws_account_id=service_resource.get_resource_account_id(),
                )
                target_policy_node = PathPolicyNode(
                    path_element_type=AwsPtrpPathNodeType.RESOURCE_POLICY,
                    policy_document_ctx=policy_document_ctx,
                    is_resource_based_policy=True,
                )
                self.graph.add_edge(target_policy_node, resource_node)

                for stmt_principal_base in service_resources_resolver.yield_resolved_stmt_principals():
                    self.logger.debug(
                        "Got resource policy of %s with %s",
                        service_resource,
                        stmt_principal_base,
                    )
                    resolved_principal_node = self._get_resolved_principal_node_base(
                        service_resource.get_resource_arn(), stmt_principal_base
                    )
                    assert isinstance(resolved_principal_node, PrincipalNodeBase)
                    self.logger.debug("connecting %s -> %s", resolved_principal_node, target_policy_node)
                    self.graph.add_edge(resolved_principal_node, target_policy_node)

    def _insert_iam_users_and_iam_groups(self):
        for iam_user in self.iam_entities.yield_iam_users():
            assert isinstance(iam_user, PrincipalAndPoliciesNodeBase)
            attached_iam_groups = self.iam_entities.get_attached_iam_groups_for_iam_user(iam_user)
            additional_policies_bases: List[PoliciesNodeBase] = [
                attached_iam_group
                for attached_iam_group in attached_iam_groups
                if isinstance(attached_iam_group, PoliciesNodeBase)
            ]
            iam_user_node = PrincipalAndPoliciesNode(base=iam_user, additional_policies_bases=additional_policies_bases)
            self.graph.add_edge(START_NODE, iam_user_node)
            self._insert_attached_policies_and_inline_policies(
                node_connect_to_policy=iam_user_node,
                attached_policies_arn=iam_user.get_attached_policies_arn(),
                inline_policies_ctx=iam_user.get_inline_policies_ctx(),
                principal_base_for_resolver=iam_user,
            )

            for iam_group in attached_iam_groups:
                assert isinstance(iam_group, PathUserGroupNodeBase)
                path_user_group_node = PathUserGroupNode(base=iam_group)
                self.graph.add_edge(iam_user_node, path_user_group_node)
                self._insert_attached_policies_and_inline_policies(
                    node_connect_to_policy=path_user_group_node,
                    attached_policies_arn=iam_group.get_attached_policies_arn(),
                    inline_policies_ctx=iam_group.get_inline_policies_ctx(),
                    principal_base_for_resolver=iam_user,
                )

    def _insert_permission_sets(self):
        if self.iam_identity_center_entities is None:
            return
        for permission_set in self.iam_identity_center_entities.yield_permission_sets():
            assert isinstance(permission_set, PathPermissionSetNodeBase)
            permission_set_node = PathPermissionSetNode(base=permission_set)
            for account_id in permission_set.accounts_assignments.keys():
                # Connect the permission set node to the corresponded iam role
                corresponded_role_arn_prefix = self.iam_identity_center_entities.generate_reserved_sso_arn_prefix(
                    account_id, permission_set.name
                )
                account_entities = self.iam_entities.iam_accounts_entities.get(account_id)
                if account_entities is None:
                    continue

                iam_role: Optional[IAMRole] = account_entities.get_role_with_arn_prefix(corresponded_role_arn_prefix)
                if iam_role is None:
                    self.logger.warning("Cannot find the corresponded role for permission set %s", permission_set)
                    continue

                path_role_node = PathRoleNode(base=iam_role)
                self.logger.debug("Connecting %s -> %s", permission_set_node, path_role_node)
                self.graph.add_edge(permission_set_node, path_role_node)

                account_assignments: Optional[Set[str]] = permission_set.get_account_assignments(account_id)

                if account_assignments is None:
                    continue

                # Connect the permission set node to the identity center users and groups of the target account which provision it
                for iam_identity_center_user in self.iam_identity_center_entities.yield_identity_center_users():
                    assert isinstance(iam_identity_center_user, PrincipalAndPoliciesNodeBase)
                    if iam_identity_center_user.user_id in account_assignments:
                        user_node = PrincipalAndPoliciesNode(
                            base=iam_identity_center_user, additional_policies_bases=[]
                        )
                        self.logger.debug("Connecting %s -> %s", user_node, permission_set_node)
                        self.graph.add_edge(user_node, permission_set_node)

                for iam_identity_center_group in self.iam_identity_center_entities.yield_identity_center_groups():
                    assert isinstance(iam_identity_center_group, PathUserGroupNodeBase)
                    path_user_group_node = PathUserGroupNode(base=iam_identity_center_group)
                    if iam_identity_center_group.group_id in account_assignments:
                        self.logger.debug("Connecting %s -> %s", path_user_group_node, permission_set_node)
                        self.graph.add_edge(path_user_group_node, permission_set_node)

    def _insert_iam_identity_center_users_and_groups(self):
        if self.iam_identity_center_entities is None:
            return

        for iam_identity_center_user in self.iam_identity_center_entities.yield_identity_center_users():
            assert isinstance(iam_identity_center_user, PrincipalAndPoliciesNodeBase)
            user_node = PrincipalAndPoliciesNode(base=iam_identity_center_user, additional_policies_bases=[])
            self.logger.debug("Connecting %s -> %s", START_NODE, user_node)
            self.graph.add_edge(START_NODE, user_node)

            for iam_identity_center_group in self.iam_identity_center_entities.yield_identity_center_groups_for_user(
                iam_identity_center_user.user_id
            ):
                assert isinstance(iam_identity_center_group, PathUserGroupNodeBase)
                path_user_group_node = PathUserGroupNode(base=iam_identity_center_group)
                self.graph.add_edge(user_node, path_user_group_node)

    def build(self) -> 'PtrpAllowedLines':
        self.logger.info("Building the Permissions resolver graph")
        self.graph.add_node(START_NODE)
        self.graph.add_node(END_NODE)

        # must run first, due to the resolving of federated users in the identity policy
        self._insert_iam_users_and_iam_groups()

        self._insert_resources()

        self._insert_iam_roles_and_trusted_entities()

        self._insert_iam_identity_center_users_and_groups()

        self._insert_permission_sets()

        self.logger.info("Finish to build the iam graph: %s", self.graph)

        return PtrpAllowedLines(
            graph=self.graph, iam_identity_center_exists=self.iam_identity_center_entities is not None
        )
