from dataclasses import dataclass
from logging import Logger
from typing import Dict, Generator, Iterable, List, Optional, Set, Tuple, Union

import networkx as nx
from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.iam.iam_roles import IAMRole, RoleSession
from aws_ptrp.iam.iam_users import IAMUser
from aws_ptrp.iam.policy.policy_document import Effect, PolicyDocument
from aws_ptrp.iam.policy.policy_document_resolver import (
    get_identity_based_resolver,
    get_resource_based_resolver,
    get_role_trust_resolver,
)
from aws_ptrp.principals import Principal
from aws_ptrp.principals.no_entity_principal import NoEntityPrincipal
from aws_ptrp.ptrp_allowed_lines.allowed_line import PtrpAllowedLine
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import (
    PathFederatedPrincipalNode,
    PathFederatedPrincipalNodeBase,
    PathNodeBase,
    PathPolicyNode,
    PathRoleNode,
    PathRoleNodeBase,
    PathUserGroupNode,
    PathUserGroupNodeBase,
    PrincipalAndPoliciesNodeBase,
    PrincipalNodeBase,
    ResourceNode,
    ResourceNodeBase,
)
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpPathNodeType
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import ServiceResourceBase, ServiceResourcesResolverBase, ServiceResourceType
from aws_ptrp.services.assume_role.assume_role_resources import AssumeRoleServiceResourcesResolver
from aws_ptrp.services.federated_user.federated_user_resources import FederatedUserPrincipal
from aws_ptrp.services.federated_user.federated_user_service import FederatedUserService

START_NODE = "START_NODE"
END_NODE = "END_NODE"


@dataclass
class PtrpAllowedLines:
    graph: nx.DiGraph

    def yield_principal_to_resource_lines(
        self,
    ) -> Generator[PtrpAllowedLine, None, None,]:
        for graph_path in nx.all_simple_paths(self.graph, source=START_NODE, target=END_NODE):
            graph_path = graph_path[1:-1]  # without the START_NODE, END_NODE
            if len(graph_path) < 3:
                raise Exception(f"Got invalid simple path in graph, expecting at least 3 nodes: {graph_path}")
            if not isinstance(graph_path[0], PrincipalAndPoliciesNodeBase):
                raise Exception(
                    f"Got invalid simple path in graph, first node is not impl PrincipalAndPoliciesNodeBase: {graph_path}"
                )
            principal_node: PrincipalAndPoliciesNodeBase = graph_path[0]

            if isinstance(graph_path[1], PathUserGroupNode):
                path_user_group_node: Optional[PathUserGroupNode] = graph_path[1]
                start_index_path_role_identity_nodes = 2
            else:
                path_user_group_node = None
                start_index_path_role_identity_nodes = 1

            if isinstance(graph_path[start_index_path_role_identity_nodes], PathPolicyNode) and isinstance(
                graph_path[start_index_path_role_identity_nodes + 1], PathFederatedPrincipalNode
            ):
                path_federated_nodes: Optional[Tuple[PathPolicyNode, PathFederatedPrincipalNode]] = (
                    graph_path[start_index_path_role_identity_nodes],
                    graph_path[start_index_path_role_identity_nodes + 1],
                )
                start_index_path_role_identity_nodes = start_index_path_role_identity_nodes + 2
            else:
                path_federated_nodes = None

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
                path_role_nodes=path_role_identity_nodes,
                target_policy_node=target_policy_node,
                resource_node=resource_node,
            )


@dataclass
class PtrpAllowedLinesBuilder:
    logger: Logger
    iam_entities: IAMEntities
    aws_actions: AwsActions
    account_resources: AwsAccountResources
    graph: nx.DiGraph = nx.DiGraph()

    def _resolve_no_entity_principal_for_principal(self, stmt_principal: Principal) -> Optional[NoEntityPrincipal]:
        if stmt_principal.is_no_entity_principal():
            return NoEntityPrincipal(stmt_principal=stmt_principal)
        else:
            return None

    def _resolve_path_node_roles_for_principal(self, stmt_principal: Principal) -> Iterable[PathRoleNodeBase]:
        if stmt_principal.is_all_principals():
            return self.iam_entities.iam_roles.values()
        elif stmt_principal.is_iam_role_principal():
            trusted_role: Optional[IAMRole] = self.iam_entities.iam_roles.get(stmt_principal.get_arn())
            return [trusted_role] if trusted_role else []
        elif stmt_principal.is_role_session_principal():
            # for role session, we can't use the principal arn to lookup the iam_role
            # because, we don't have all the information we need to create the iam_role arn from the arn of the role session
            # needs to go over all the iam_roles and compare the aws account id + role name
            # Example
            # role session arn: arn:aws:sts::982269985744:assumed-role/AWSReservedSSO_AdministratorAccess_3924a5ba0a9f57fd/alon@satoricyber.com
            # role_arn (includes also path) arn:aws:iam::982269985744:role/aws-reserved/sso.amazonaws.com/eu-west-2/AWSReservedSSO_AdministratorAccess_3924a5ba0a9f57fd
            # the role path is missing (/aws-reserved/sso.amazonaws.com/eu-west-2/)
            role_session_role_name = stmt_principal.get_role_name()
            role_session_account_id = stmt_principal.get_account_id()
            for iam_role in self.iam_entities.iam_roles.values():
                if iam_role.role_name == role_session_role_name and iam_role.aws_account_id == role_session_account_id:
                    role_session = RoleSession(iam_role=iam_role, role_session_principal=stmt_principal)
                    return [role_session]
        return []

    def _resolve_federated_user_for_principal(
        self, stmt_principal: Principal
    ) -> Iterable[PathFederatedPrincipalNodeBase]:
        if stmt_principal.is_all_principals():
            all_federated_users: Optional[Set[ServiceResourceBase]] = self.account_resources.account_resources.get(
                FederatedUserService()
            )
            if all_federated_users:
                return [x for x in all_federated_users if isinstance(x, PathFederatedPrincipalNodeBase)]
        # No need to check is_iam_user_principal, is_iam_user_account.
        # if stmt principal is federated user, and on the resource based policy includes allow to IAM user/ IAM account
        # then the result is deny.
        # check the table of (Principal making the request) here
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
        # In addition, calling this function from the iam_role trusted policy is not relevant.
        # federated user are not allow to assume role
        elif stmt_principal.is_federated_user_principal():
            return [FederatedUserPrincipal(federated_principal=stmt_principal)]
        return []

    def _resolve_iam_users_for_principal(self, stmt_principal: Principal) -> Iterable[IAMUser]:
        if stmt_principal.is_all_principals():
            return self.iam_entities.iam_users.values()
        elif stmt_principal.is_iam_user_principal():
            iam_user: Optional[IAMUser] = self.iam_entities.iam_users.get(stmt_principal.get_arn())
            return [iam_user] if iam_user else []
        elif stmt_principal.is_iam_user_account():
            ret: List[IAMUser] = []
            for iam_user in self.iam_entities.iam_users.values():
                if stmt_principal.contains(iam_user.identity_principal):
                    ret.append(iam_user)
            return ret
        return []

    def _yield_resolved_principal_nodes(
        self,
        stmt_principal: Principal,
    ) -> Generator[PrincipalNodeBase, None, None]:
        # All Principals / IAM Role / Role Session
        path_roles_node_base: Iterable[PathRoleNodeBase] = self._resolve_path_node_roles_for_principal(stmt_principal)
        for path_role_base in path_roles_node_base:
            assert isinstance(path_role_base, PathRoleNodeBase)
            path_role_node = PathRoleNode(base=path_role_base, note="")
            if isinstance(path_role_base, RoleSession):
                # need to connect the role session node to its matched iam role
                path_iam_role_node = PathRoleNode(base=path_role_base.iam_role, note="")
                assert isinstance(path_iam_role_node, PathRoleNodeBase)
                self.graph.add_edge(path_iam_role_node, path_role_node)
            yield path_role_node

        # All Principals / IAM User / IAM Account Users
        principal_iam_users: Iterable[IAMUser] = self._resolve_iam_users_for_principal(stmt_principal)
        for principal_iam_user in principal_iam_users:
            assert isinstance(principal_iam_user, PrincipalAndPoliciesNodeBase)
            self.graph.add_edge(START_NODE, principal_iam_user)
            yield principal_iam_user

        # All Principals / Federated User
        federated_user_nodes_base: Iterable[
            PathFederatedPrincipalNodeBase
        ] = self._resolve_federated_user_for_principal(stmt_principal)
        for federated_user_node_base in federated_user_nodes_base:
            assert isinstance(federated_user_node_base, PathFederatedPrincipalNodeBase)
            federated_user_node = PathFederatedPrincipalNode(base=federated_user_node_base, note="")
            yield federated_user_node

        # All Principals / No Entity principal
        no_entity_principal: Optional[NoEntityPrincipal] = self._resolve_no_entity_principal_for_principal(
            stmt_principal
        )
        if no_entity_principal:
            assert isinstance(no_entity_principal, PrincipalAndPoliciesNodeBase)
            self.graph.add_edge(START_NODE, no_entity_principal)
            yield no_entity_principal

    def _yield_resolved_service_resources_for_identity_based_policy(
        self, identity_principal: Principal, policy_document: PolicyDocument, path_arn: str, path_name: str
    ) -> Generator[Tuple[ServiceResourceType, ServiceResourceBase], None, None,]:
        service_resources_resolver: Optional[
            Dict[ServiceResourceType, ServiceResourcesResolverBase]
        ] = get_identity_based_resolver(
            logger=self.logger,
            policy_documents=[policy_document],
            identity_principal=identity_principal,
            effect=Effect.Allow,
            aws_actions=self.aws_actions,
            account_resources=self.account_resources,
        )

        if service_resources_resolver:
            for service_type, service_resource_resolver in service_resources_resolver.items():
                for service_resource in service_resource_resolver.yield_resolved_resources(identity_principal):
                    self.logger.debug(
                        "For %s, got resolved resource %s in: %s: %s",
                        identity_principal,
                        service_resource,
                        path_arn,
                        path_name,
                    )
                    yield service_type, service_resource

    def _connect_path_policy_node_with_resolved_service_resource(
        self,
        identity_principal: Principal,
        path_policy_node: PathPolicyNode,
        service_resource_type: ServiceResourceType,
        service_resource: ServiceResourceBase,
    ):

        if isinstance(service_resource, ResourceNodeBase):
            resource_node = ResourceNode(base=service_resource, service_resource_type=service_resource_type, note="")
            self.graph.add_edge(path_policy_node, resource_node)
        elif (
            (identity_principal.is_iam_user_principal() or identity_principal.is_iam_user_account())
            and path_policy_node.is_resource_based_policy is False
            and isinstance(service_resource_type, FederatedUserService)
            and isinstance(service_resource, FederatedUserPrincipal)
        ):
            # special handling for federated user
            # connect the path policy node to the federated principal node
            assert isinstance(service_resource, PathFederatedPrincipalNodeBase)
            federated_principal_node = PathFederatedPrincipalNode(base=service_resource, note="")
            self.logger.debug("connecting %s -> %s", path_policy_node, federated_principal_node)
            self.graph.add_edge(path_policy_node, federated_principal_node)

    def _insert_attached_policies_and_inline_policies(
        self,
        node_connect_to_target: Union[PrincipalNodeBase, PathNodeBase],
        attached_policies_arn: List[str],
        inline_policies_and_names: List[Tuple[PolicyDocument, str]],
        identity_principal_for_resolver: Principal,
    ):
        if isinstance(node_connect_to_target, PrincipalNodeBase):
            arn_for_inline: str = node_connect_to_target.get_stmt_principal().get_arn()
        elif isinstance(node_connect_to_target, PathNodeBase):
            arn_for_inline = node_connect_to_target.get_path_arn()
        else:
            assert False

        for attached_policy_arn in attached_policies_arn:
            iam_policy = self.iam_entities.iam_policies[attached_policy_arn]
            for service_type, service_resource in self._yield_resolved_service_resources_for_identity_based_policy(
                identity_principal=identity_principal_for_resolver,
                policy_document=iam_policy.policy_document,
                path_arn=iam_policy.policy.arn,
                path_name=iam_policy.policy.policy_name,
            ):
                path_policy_node = PathPolicyNode(
                    path_element_type=AwsPtrpPathNodeType.IAM_POLICY,
                    path_arn=iam_policy.policy.arn,
                    path_name=iam_policy.policy.policy_name,
                    policy_document=iam_policy.policy_document,
                    is_resource_based_policy=False,
                    note="",
                )
                self.graph.add_edge(node_connect_to_target, path_policy_node)
                self._connect_path_policy_node_with_resolved_service_resource(
                    identity_principal=identity_principal_for_resolver,
                    path_policy_node=path_policy_node,
                    service_resource_type=service_type,
                    service_resource=service_resource,
                )
        for inline_policy, policy_name in inline_policies_and_names:
            for service_type, service_resource in self._yield_resolved_service_resources_for_identity_based_policy(
                identity_principal=identity_principal_for_resolver,
                policy_document=inline_policy,
                path_arn=arn_for_inline,
                path_name=policy_name,
            ):
                path_policy_node = PathPolicyNode(
                    path_element_type=AwsPtrpPathNodeType.IAM_INLINE_POLICY,
                    path_arn=arn_for_inline,
                    path_name=policy_name,
                    policy_document=inline_policy,
                    is_resource_based_policy=False,
                    note="",
                )
                self.graph.add_edge(node_connect_to_target, path_policy_node)
                self._connect_path_policy_node_with_resolved_service_resource(
                    identity_principal=identity_principal_for_resolver,
                    path_policy_node=path_policy_node,
                    service_resource_type=service_type,
                    service_resource=service_resource,
                )

    def _insert_iam_roles_and_trusted_entities(self):
        for iam_role in self.iam_entities.iam_roles.values():
            # Check the role's trusted entities
            role_trust_service_principal_resolver: Optional[
                AssumeRoleServiceResourcesResolver
            ] = get_role_trust_resolver(
                logger=self.logger,
                role_trust_policy=iam_role.assume_role_policy_document,
                iam_role_arn=iam_role.arn,
                effect=Effect.Allow,
                aws_actions=self.aws_actions,
                account_resources=self.account_resources,
            )

            if role_trust_service_principal_resolver is None:
                continue

            assert isinstance(iam_role, PathRoleNodeBase)
            path_role_node = PathRoleNode(base=iam_role, note="")
            for trusted_principal_to_resolve in role_trust_service_principal_resolver.yield_trusted_principals(
                iam_role
            ):
                self.logger.debug(
                    "Got role name %s with resolved trusted principal %s",
                    iam_role.role_name,
                    trusted_principal_to_resolve,
                )
                for resolved_principal_node in self._yield_resolved_principal_nodes(trusted_principal_to_resolve):
                    assert isinstance(resolved_principal_node, PrincipalNodeBase)

                    self.graph.add_edge(resolved_principal_node, path_role_node)
                    self._insert_attached_policies_and_inline_policies(
                        node_connect_to_target=path_role_node,
                        attached_policies_arn=iam_role.get_attached_policies_arn(),
                        inline_policies_and_names=iam_role.get_inline_policies_and_names(),
                        identity_principal_for_resolver=resolved_principal_node.get_stmt_principal(),
                    )

    def _insert_resources(self):
        for service_resources_type, service_resources in self.account_resources.account_resources.items():
            for service_resource in service_resources:
                if not isinstance(service_resource, ResourceNodeBase):
                    continue
                resource_node = ResourceNode(
                    base=service_resource, service_resource_type=service_resources_type, note=""
                )
                self.graph.add_edge(resource_node, END_NODE)

                service_resource_policy: Optional[PolicyDocument] = service_resource.get_resource_policy()
                if service_resource_policy is None:
                    continue

                service_resources_resolver: Optional[ServiceResourcesResolverBase] = get_resource_based_resolver(
                    logger=self.logger,
                    policy_document=service_resource_policy,
                    service_resource_type=service_resources_type,
                    resource_arn=service_resource.get_resource_arn(),
                    effect=Effect.Allow,
                    aws_actions=self.aws_actions,
                    account_resources=self.account_resources,
                )
                if service_resources_resolver is None:
                    continue

                target_policy_node = PathPolicyNode(
                    path_element_type=AwsPtrpPathNodeType.RESOURCE_POLICY,
                    path_arn=service_resource.get_resource_arn(),
                    path_name=service_resource.get_resource_name(),
                    policy_document=service_resource_policy,
                    is_resource_based_policy=True,
                    note="",
                )
                self.graph.add_edge(target_policy_node, resource_node)

                for stmt_principal in service_resources_resolver.yield_resolved_stmt_principals():
                    self.logger.debug(
                        "Got resource policy of %s with %s",
                        service_resource,
                        stmt_principal,
                    )

                    for resolved_principal_node in self._yield_resolved_principal_nodes(stmt_principal):
                        assert isinstance(resolved_principal_node, PrincipalNodeBase)
                        self.logger.debug("connecting %s -> %s", resolved_principal_node, target_policy_node)
                        self.graph.add_edge(resolved_principal_node, target_policy_node)

    def _insert_iam_users_and_iam_groups(self):
        for iam_user in self.iam_entities.iam_users.values():
            assert isinstance(iam_user, PrincipalAndPoliciesNodeBase)
            self.graph.add_edge(START_NODE, iam_user)
            self._insert_attached_policies_and_inline_policies(
                node_connect_to_target=iam_user,
                attached_policies_arn=iam_user.get_attached_policies_arn(),
                inline_policies_and_names=iam_user.get_inline_policies_and_names(),
                identity_principal_for_resolver=iam_user.identity_principal,
            )

            for iam_group in self.iam_entities.iam_groups.values():
                # if current iam_user in part of this iam_group, edged them (and also it relevant roles)
                if iam_user.user_id not in iam_group.group_user_ids:
                    continue

                assert isinstance(iam_group, PathUserGroupNodeBase)
                path_user_group_node = PathUserGroupNode(base=iam_group, note="")
                self.graph.add_edge(iam_user, path_user_group_node)
                self._insert_attached_policies_and_inline_policies(
                    node_connect_to_target=path_user_group_node,
                    attached_policies_arn=iam_group.get_attached_policies_arn(),
                    inline_policies_and_names=iam_group.get_inline_policies_and_names(),
                    identity_principal_for_resolver=iam_user.identity_principal,
                )

    def build(self) -> 'PtrpAllowedLines':
        self.logger.info("Building the Permissions resolver graph")
        self.graph.add_node(START_NODE)
        self.graph.add_node(END_NODE)

        self._insert_resources()

        self._insert_iam_roles_and_trusted_entities()

        self._insert_iam_users_and_iam_groups()

        self.logger.info("Finish to build the iam graph: %s", self.graph)

        return PtrpAllowedLines(graph=self.graph)
