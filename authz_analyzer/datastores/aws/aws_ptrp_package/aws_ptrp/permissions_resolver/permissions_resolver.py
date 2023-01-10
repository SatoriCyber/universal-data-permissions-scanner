from dataclasses import dataclass
from logging import Logger
from typing import Optional, List, Iterable, Generator, Dict, Tuple, Union
import networkx as nx

from aws_ptrp.permissions_resolver.identity_to_resource_nodes_base import (
    IdentityNodeBase,
    TargetPolicyNode,
    ResourceNodeBase,
    PathRoleIdentityNode,
    PathRoleIdentityNodeBase,
    PathIdentityPoliciesNode,
    PathIdentityPoliciesNodeBase,
)
from authz_analyzer.models.model import (
    AuthzPathElementType,
)

from aws_ptrp.permissions_resolver.identity_to_resource_line import IdentityToResourceLine
from aws_ptrp.services import ServiceResourcesResolverBase, ServiceResourceType
from aws_ptrp.actions.account_actions import AwsAccountActions
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.services.assume_role.assume_role_resources import AssumeRoleServiceResourcesResolver
from aws_ptrp.iam.policy.policy_document_resolver import (
    get_role_trust_resolver,
    get_resource_based_resolver,
    get_identity_based_resolver,
)
from aws_ptrp.iam.policy.principal import StmtPrincipal
from aws_ptrp.principals.no_entity_principal import NoEntityPrincipal
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.iam.iam_roles import IAMRole, IAMRoleSession
from aws_ptrp.iam.iam_users import IAMUser


START_NODE = "START_NODE"
END_NODE = "END_NODE"


@dataclass
class PermissionsResolver:
    graph: nx.DiGraph

    def yield_identity_to_resource_lines(
        self,
    ) -> Generator[IdentityToResourceLine, None, None,]:
        for path in nx.all_simple_paths(self.graph, source=START_NODE, target=END_NODE):
            path = path[1:-1]  # without the START_NODE, END_NODE
            if len(path) < 3:
                raise Exception(f"Got invalid simple path in graph, expecting at least 3 nodes: {path}")
            if not isinstance(path[0], IdentityNodeBase):
                raise Exception(f"Got invalid simple path in graph, first node is not impl IdentityNodeBase: {path}")
            identity_node: IdentityNodeBase = path[0]

            if isinstance(path[1], PathIdentityPoliciesNode):
                path_identity_policies_node: Optional[PathIdentityPoliciesNode] = path[1]
                start_index_path_role_identity_nodes = 2
                if len(path) < 4:
                    raise Exception(
                        f"Got invalid simple path in graph with second node PathIdentityPoliciesNode, expecting at least 4 nodes: {path}"
                    )
            else:
                path_identity_policies_node = None
                start_index_path_role_identity_nodes = 1

            all_path_role_identity_nodes_valid = all(
                isinstance(path_element, PathRoleIdentityNode)
                for path_element in path[start_index_path_role_identity_nodes:-2]
            )
            if not all_path_role_identity_nodes_valid:
                raise Exception(
                    f"Got invalid simple path in graph, not all nodes are impl PathRoleIdentityNode: {path[start_index_path_role_identity_nodes:-2]}"
                )
            path_role_identity_nodes: List[PathRoleIdentityNode] = path[start_index_path_role_identity_nodes:-2]

            if not isinstance(path[-2], TargetPolicyNode):
                raise Exception(
                    f"Got invalid simple path in graph, last_node-1 is not impl TargetPolicyNode: {path[-2]}"
                )
            target_policy_node: TargetPolicyNode = path[-2]

            if not isinstance(path[-1], ResourceNodeBase):
                raise Exception(f"Got invalid simple path in graph, last node is not impl ResourceNodeBase: {path[-1]}")
            resource_node: ResourceNodeBase = path[-1]

            yield IdentityToResourceLine(
                identity_node=identity_node,
                path_identity_policies_node=path_identity_policies_node,
                path_role_identity_nodes=path_role_identity_nodes,
                target_policy_node=target_policy_node,
                resource_node=resource_node,
            )


@dataclass
class PermissionsResolverBuilder:
    logger: Logger
    iam_entities: IAMEntities
    account_actions: AwsAccountActions
    account_resources: AwsAccountResources
    graph: nx.DiGraph = nx.DiGraph()

    def get_no_entity_principal_for_principal(self, stmt_principal: StmtPrincipal) -> Optional[NoEntityPrincipal]:
        if stmt_principal.is_no_entity_principal():
            return NoEntityPrincipal(stmt_principal=stmt_principal)
        else:
            return None

    def get_path_node_roles_for_principal(self, stmt_principal: StmtPrincipal) -> Iterable[PathRoleIdentityNodeBase]:
        if stmt_principal.is_all_principals():
            return self.iam_entities.iam_roles.values()
        elif stmt_principal.is_role_principal():
            trusted_role: Optional[IAMRole] = self.iam_entities.iam_roles.get(stmt_principal.get_arn())
            return [trusted_role] if trusted_role else []
        elif stmt_principal.is_role_session_principal():
            role: Optional[IAMRole] = self.iam_entities.iam_roles.get(stmt_principal.get_arn())
            if role:
                return [IAMRoleSession(role=role, session_name=stmt_principal.get_name())]
        return []

    def get_iam_roles_for_principal(self, stmt_principal: StmtPrincipal) -> Iterable[IAMUser]:
        if stmt_principal.is_all_principals():
            return self.iam_entities.iam_users.values()
        elif stmt_principal.is_iam_user_principal():
            ret: List[IAMUser] = []
            for iam_user in self.iam_entities.iam_users.values():
                if stmt_principal.contains(iam_user.identity_principal):
                    ret.append(iam_user)
            return ret
        else:
            return []

    def _resolve_stmt_principal_to_nodes_and_connect(
        self,
        stmt_principal: StmtPrincipal,
        node_to_connect: Union[TargetPolicyNode, PathRoleIdentityNode],
    ):
        if isinstance(node_to_connect, TargetPolicyNode):
            node_to_connect_arn: str = node_to_connect.path_arn
        elif isinstance(node_to_connect, PathRoleIdentityNode):
            node_to_connect_arn = node_to_connect.path_role_identity_base.get_path_arn()
        else:
            assert False

        path_roles_identity_base: Iterable[PathRoleIdentityNodeBase] = self.get_path_node_roles_for_principal(
            stmt_principal
        )
        for path_role_identity_base in path_roles_identity_base:
            if path_role_identity_base.get_path_arn() != node_to_connect_arn:
                assert isinstance(path_role_identity_base, PathRoleIdentityNodeBase)
                path_role_identity = PathRoleIdentityNode(path_role_identity_base=path_role_identity_base, note="")
                self.graph.add_edge(path_role_identity, node_to_connect)

        no_entity_principal: Optional[NoEntityPrincipal] = self.get_no_entity_principal_for_principal(stmt_principal)
        if no_entity_principal:
            assert isinstance(no_entity_principal, IdentityNodeBase)
            self.graph.add_edge(START_NODE, no_entity_principal)
            self.graph.add_edge(no_entity_principal, node_to_connect)

        iam_users: Iterable[IAMUser] = self.get_iam_roles_for_principal(stmt_principal)
        for iam_user in iam_users:
            assert isinstance(iam_user, IdentityNodeBase)
            self.graph.add_edge(START_NODE, iam_user)
            self.graph.add_edge(iam_user, node_to_connect)

    def _connect_target_policy_node_to_resources(
        self,
        identity_principal: StmtPrincipal,
        target_policy_node: TargetPolicyNode,
    ):
        service_resources_resolver: Optional[
            Dict[ServiceResourceType, ServiceResourcesResolverBase]
        ] = get_identity_based_resolver(
            logger=self.logger,
            policy_document=target_policy_node.policy_document,
            identity_principal=identity_principal,
            account_actions=self.account_actions,
            account_resources=self.account_resources,
        )
        if service_resources_resolver is None:
            return

        for service_resource_resolver in service_resources_resolver.values():
            for service_resource in service_resource_resolver.yield_resolved_resources(identity_principal):
                self.logger.debug(
                    "For %s, got resolved resource %s in: %s: %s",
                    identity_principal,
                    service_resource,
                    target_policy_node.path_arn,
                    target_policy_node.path_name,
                )
                if not isinstance(service_resource, ResourceNodeBase):
                    continue
                self.graph.add_edge(target_policy_node, service_resource)

    def _insert_attached_policies_and_inline_policies(
        self,
        identity_node: Union[IdentityNodeBase, PathRoleIdentityNode, PathIdentityPoliciesNode],
        node_arn: str,
        attached_policies_arn: List[str],
        inline_policies_and_names: List[Tuple[PolicyDocument, str]],
        identity_principal: StmtPrincipal,
    ):
        assert (
            isinstance(identity_node, IdentityNodeBase)
            or isinstance(identity_node, PathRoleIdentityNode)
            or isinstance(identity_node, PathIdentityPoliciesNode)
        )
        for attached_policy_arn in attached_policies_arn:
            iam_policy = self.iam_entities.iam_policies[attached_policy_arn]
            target_policy_node = TargetPolicyNode(
                path_element_type=AuthzPathElementType.IAM_POLICY,
                path_arn=iam_policy.policy.arn,
                path_name=iam_policy.policy.policy_name,
                policy_document=iam_policy.policy_document,
                note="",
            )
            self.graph.add_edge(identity_node, target_policy_node)
            self._connect_target_policy_node_to_resources(identity_principal, target_policy_node)
        for inline_policy, policy_name in inline_policies_and_names:
            target_policy_node = TargetPolicyNode(
                path_element_type=AuthzPathElementType.IAM_INLINE_POLICY,
                path_arn=node_arn,
                path_name=policy_name,
                policy_document=inline_policy,
                note="",
            )
            self.graph.add_edge(identity_node, target_policy_node)
            self._connect_target_policy_node_to_resources(identity_principal, target_policy_node)

    def _insert_iam_roles_and_trusted_entities(self):
        for iam_role in self.iam_entities.iam_roles.values():
            # Check the role's trusted entities
            role_trust_service_principal_resolver: Optional[
                AssumeRoleServiceResourcesResolver
            ] = get_role_trust_resolver(
                logger=self.logger,
                role_trust_policy=iam_role.assume_role_policy_document,
                iam_role_arn=iam_role.arn,
                account_actions=self.account_actions,
                account_resources=self.account_resources,
            )
            if role_trust_service_principal_resolver is None:
                continue

            assert isinstance(iam_role, PathRoleIdentityNodeBase)
            path_role_identity_node = PathRoleIdentityNode(path_role_identity_base=iam_role, note="")

            for trusted_principal in role_trust_service_principal_resolver.yield_trusted_principals(iam_role):
                self.logger.debug(
                    "Got role name %s with resolved trusted principal %s", iam_role.role_name, trusted_principal
                )
                self._resolve_stmt_principal_to_nodes_and_connect(trusted_principal, path_role_identity_node)
                self._insert_attached_policies_and_inline_policies(
                    identity_node=path_role_identity_node,
                    node_arn=iam_role.arn,
                    attached_policies_arn=iam_role.get_attached_policies_arn(),
                    inline_policies_and_names=iam_role.get_inline_policies_and_names(),
                    identity_principal=trusted_principal,
                )

    def _insert_resource_based_policies(self):
        for service_resources_type, service_resources in self.account_resources.account_resources.items():
            for service_resource in service_resources:  # type: ResourceNodeBase
                if not isinstance(service_resource, ResourceNodeBase):
                    continue

                service_resource_policy: Optional[PolicyDocument] = service_resource.get_resource_policy()
                if service_resource_policy is None:
                    continue

                self.graph.add_edge(service_resource, END_NODE)
                service_resources_resolver: Optional[ServiceResourcesResolverBase] = get_resource_based_resolver(
                    logger=self.logger,
                    policy_document=service_resource_policy,
                    service_resource_type=service_resources_type,
                    account_actions=self.account_actions,
                    account_resources=self.account_resources,
                )
                if service_resources_resolver is None:
                    continue

                target_policy_node = TargetPolicyNode(
                    path_element_type=AuthzPathElementType.RESOURCE_POLICY,
                    path_arn=service_resource.get_resource_arn(),
                    path_name=service_resource.get_resource_name(),
                    policy_document=service_resource_policy,
                    note="",
                )
                self.graph.add_edge(target_policy_node, service_resource)

                for stmt_principal in service_resources_resolver.yield_resolved_stmt_principals():
                    self.logger.debug(
                        "Got resource policy of %s with %s",
                        service_resource,
                        stmt_principal,
                    )

                    self._resolve_stmt_principal_to_nodes_and_connect(stmt_principal, target_policy_node)

    def _insert_iam_users_and_iam_groups(self):
        for iam_user in self.iam_entities.iam_users.values():
            assert isinstance(iam_user, IdentityNodeBase)
            self.graph.add_edge(START_NODE, iam_user)
            self._insert_attached_policies_and_inline_policies(
                identity_node=iam_user,
                node_arn=iam_user.get_stmt_principal().get_arn(),
                attached_policies_arn=iam_user.get_attached_policies_arn(),
                inline_policies_and_names=iam_user.get_inline_policies_and_names(),
                identity_principal=iam_user.identity_principal,
            )

            for iam_group in self.iam_entities.iam_groups.values():
                # if current iam_user in part of this iam_group, edged them (and also it relevant roles)
                if iam_user.user_id not in iam_group.group_user_ids:
                    continue

                assert isinstance(iam_group, PathIdentityPoliciesNodeBase)
                identity_policies_node = PathIdentityPoliciesNode(path_identity_policies_base=iam_group, note="")
                self.graph.add_edge(iam_user, identity_policies_node)
                self._insert_attached_policies_and_inline_policies(
                    identity_node=identity_policies_node,
                    node_arn=iam_group.arn,
                    attached_policies_arn=iam_group.get_attached_policies_arn(),
                    inline_policies_and_names=iam_group.get_inline_policies_and_names(),
                    identity_principal=iam_user.identity_principal,
                )

    def build(self) -> 'PermissionsResolver':
        self.logger.info("Building the Permissions resolver graph")
        self.graph.add_node(START_NODE)
        self.graph.add_node(END_NODE)

        self._insert_resource_based_policies()

        self._insert_iam_roles_and_trusted_entities()

        self._insert_iam_users_and_iam_groups()

        self.logger.info("Finish to build the iam graph: %s", self.graph)

        return PermissionsResolver(graph=self.graph)
