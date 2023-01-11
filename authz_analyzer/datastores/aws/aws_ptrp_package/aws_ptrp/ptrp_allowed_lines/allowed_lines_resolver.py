from dataclasses import dataclass
from logging import Logger
from typing import Optional, List, Iterable, Generator, Dict, Tuple, Union
import networkx as nx

from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import (
    PrincipalNodeBase,
    TargetPolicyNode,
    ResourceNodeBase,
    PathRoleNode,
    PathRoleNodeBase,
    PathPrincipalPoliciesNode,
    PathPrincipalPoliciesNodeBase,
)
from aws_ptrp.ptrp_allowed_lines.allowed_line import PtrpAllowedLine
from aws_ptrp.services import ServiceResourcesResolverBase, ServiceResourceType
from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.services.assume_role.assume_role_resources import AssumeRoleServiceResourcesResolver
from aws_ptrp.iam.policy.policy_document_resolver import (
    get_role_trust_resolver,
    get_resource_based_resolver,
    get_identity_based_resolver,
)
from aws_ptrp.principals import Principal
from aws_ptrp.principals.no_entity_principal import NoEntityPrincipal
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.iam.iam_roles import IAMRole, IAMRoleSession
from aws_ptrp.iam.iam_users import IAMUser

from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpPathNodeType


START_NODE = "START_NODE"
END_NODE = "END_NODE"


@dataclass
class PtrpAllowedLines:
    graph: nx.DiGraph

    def yield_principal_to_resource_lines(
        self,
    ) -> Generator[PtrpAllowedLine, None, None,]:
        for path in nx.all_simple_paths(self.graph, source=START_NODE, target=END_NODE):
            path = path[1:-1]  # without the START_NODE, END_NODE
            if len(path) < 3:
                raise Exception(f"Got invalid simple path in graph, expecting at least 3 nodes: {path}")
            if not isinstance(path[0], PrincipalNodeBase):
                raise Exception(f"Got invalid simple path in graph, first node is not impl PrincipalNodeBase: {path}")
            identity_node: PrincipalNodeBase = path[0]

            if isinstance(path[1], PathPrincipalPoliciesNode):
                path_identity_policies_node: Optional[PathPrincipalPoliciesNode] = path[1]
                start_index_path_role_identity_nodes = 2
                if len(path) < 4:
                    raise Exception(
                        f"Got invalid simple path in graph with second node PathPrincipalPoliciesNode, expecting at least 4 nodes: {path}"
                    )
            else:
                path_identity_policies_node = None
                start_index_path_role_identity_nodes = 1

            all_path_role_identity_nodes_valid = all(
                isinstance(path_element, PathRoleNode) for path_element in path[start_index_path_role_identity_nodes:-2]
            )
            if not all_path_role_identity_nodes_valid:
                raise Exception(
                    f"Got invalid simple path in graph, not all nodes are impl PathRoleNode: {path[start_index_path_role_identity_nodes:-2]}"
                )
            path_role_identity_nodes: List[PathRoleNode] = path[start_index_path_role_identity_nodes:-2]

            if not isinstance(path[-2], TargetPolicyNode):
                raise Exception(
                    f"Got invalid simple path in graph, last_node-1 is not impl TargetPolicyNode: {path[-2]}"
                )
            target_policy_node: TargetPolicyNode = path[-2]

            if not isinstance(path[-1], ResourceNodeBase):
                raise Exception(f"Got invalid simple path in graph, last node is not impl ResourceNodeBase: {path[-1]}")
            resource_node: ResourceNodeBase = path[-1]

            yield PtrpAllowedLine(
                principal_node=identity_node,
                path_principal_policies_node=path_identity_policies_node,
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

    def get_no_entity_principal_for_principal(self, stmt_principal: Principal) -> Optional[NoEntityPrincipal]:
        if stmt_principal.is_no_entity_principal():
            return NoEntityPrincipal(stmt_principal=stmt_principal)
        else:
            return None

    def get_path_node_roles_for_principal(self, stmt_principal: Principal) -> Iterable[PathRoleNodeBase]:
        if stmt_principal.is_all_principals():
            return self.iam_entities.iam_roles.values()
        elif stmt_principal.is_role_principal():
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
            role_session_account_id = stmt_principal.get_account_id()
            role_session_role_name = stmt_principal.get_role_name()
            for iam_role in self.iam_entities.iam_roles.values():
                if iam_role.role_name == role_session_role_name and role_session_account_id == iam_role.aws_account_id:
                    role_session = IAMRoleSession(role=iam_role, role_session_principal=stmt_principal)
                    return [role_session]
        return []

    def get_iam_roles_for_principal(self, stmt_principal: Principal) -> Iterable[IAMUser]:
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
        stmt_principal: Principal,
        node_to_connect: Union[TargetPolicyNode, PathRoleNode],
    ):
        if isinstance(node_to_connect, TargetPolicyNode):
            node_to_connect_arn: str = node_to_connect.path_arn
        elif isinstance(node_to_connect, PathRoleNode):
            node_to_connect_arn = node_to_connect.path_role_base.get_path_arn()
        else:
            assert False

        path_roles_identity_base: Iterable[PathRoleNodeBase] = self.get_path_node_roles_for_principal(stmt_principal)
        for path_role_base in path_roles_identity_base:
            if path_role_base.get_path_arn() != node_to_connect_arn:
                assert isinstance(path_role_base, PathRoleNodeBase)
                path_role_node = PathRoleNode(path_role_base=path_role_base, note="")
                self.graph.add_edge(path_role_node, node_to_connect)
                if isinstance(path_role_base, IAMRoleSession):
                    # need to connect the role session node to its matched iam role
                    path_iam_role_node = PathRoleNode(path_role_base=path_role_base.role, note="")
                    self.graph.add_edge(path_iam_role_node, path_role_node)

        no_entity_principal: Optional[NoEntityPrincipal] = self.get_no_entity_principal_for_principal(stmt_principal)
        if no_entity_principal:
            assert isinstance(no_entity_principal, PrincipalNodeBase)
            self.graph.add_edge(START_NODE, no_entity_principal)
            self.graph.add_edge(no_entity_principal, node_to_connect)

        iam_users: Iterable[IAMUser] = self.get_iam_roles_for_principal(stmt_principal)
        for iam_user in iam_users:
            assert isinstance(iam_user, PrincipalNodeBase)
            self.graph.add_edge(START_NODE, iam_user)
            self.graph.add_edge(iam_user, node_to_connect)

    def _connect_target_policy_node_to_resources(
        self,
        identity_principal: Principal,
        target_policy_node: TargetPolicyNode,
    ):
        service_resources_resolver: Optional[
            Dict[ServiceResourceType, ServiceResourcesResolverBase]
        ] = get_identity_based_resolver(
            logger=self.logger,
            policy_document=target_policy_node.policy_document,
            identity_principal=identity_principal,
            aws_actions=self.aws_actions,
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
        node_connect_to_target: Union[PrincipalNodeBase, PathRoleNode, PathPrincipalPoliciesNode],
        attached_policies_arn: List[str],
        inline_policies_and_names: List[Tuple[PolicyDocument, str]],
        identity_principal_for_resolver: Principal,
    ):
        if isinstance(node_connect_to_target, PrincipalNodeBase):
            arn_for_inline: str = node_connect_to_target.get_stmt_principal().get_arn()
        elif isinstance(node_connect_to_target, PathRoleNode):
            arn_for_inline = node_connect_to_target.path_role_base.get_path_arn()
        elif isinstance(node_connect_to_target, PathPrincipalPoliciesNode):
            arn_for_inline = node_connect_to_target.path_principal_policies_base.get_path_arn()
        else:
            assert False

        for attached_policy_arn in attached_policies_arn:
            iam_policy = self.iam_entities.iam_policies[attached_policy_arn]
            target_policy_node = TargetPolicyNode(
                path_element_type=AwsPtrpPathNodeType.IAM_POLICY,
                path_arn=iam_policy.policy.arn,
                path_name=iam_policy.policy.policy_name,
                policy_document=iam_policy.policy_document,
                is_resource_based_policy=False,
                note="",
            )
            self.graph.add_edge(node_connect_to_target, target_policy_node)
            self._connect_target_policy_node_to_resources(identity_principal_for_resolver, target_policy_node)
        for inline_policy, policy_name in inline_policies_and_names:
            target_policy_node = TargetPolicyNode(
                path_element_type=AwsPtrpPathNodeType.IAM_INLINE_POLICY,
                path_arn=arn_for_inline,
                path_name=policy_name,
                policy_document=inline_policy,
                is_resource_based_policy=False,
                note="",
            )
            self.graph.add_edge(node_connect_to_target, target_policy_node)
            self._connect_target_policy_node_to_resources(identity_principal_for_resolver, target_policy_node)

    def _insert_iam_roles_and_trusted_entities(self):
        for iam_role in self.iam_entities.iam_roles.values():
            # Check the role's trusted entities
            role_trust_service_principal_resolver: Optional[
                AssumeRoleServiceResourcesResolver
            ] = get_role_trust_resolver(
                logger=self.logger,
                role_trust_policy=iam_role.assume_role_policy_document,
                iam_role_arn=iam_role.arn,
                aws_actions=self.aws_actions,
                account_resources=self.account_resources,
            )

            if role_trust_service_principal_resolver is None:
                continue

            assert isinstance(iam_role, PathRoleNodeBase)
            path_role_node = PathRoleNode(path_role_base=iam_role, note="")
            for trusted_principal in role_trust_service_principal_resolver.yield_trusted_principals(iam_role):
                self.logger.debug(
                    "Got role name %s with resolved trusted principal %s", iam_role.role_name, trusted_principal
                )
                self._resolve_stmt_principal_to_nodes_and_connect(trusted_principal, path_role_node)
                self._insert_attached_policies_and_inline_policies(
                    node_connect_to_target=path_role_node,
                    attached_policies_arn=iam_role.get_attached_policies_arn(),
                    inline_policies_and_names=iam_role.get_inline_policies_and_names(),
                    identity_principal_for_resolver=trusted_principal,
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
                    aws_actions=self.aws_actions,
                    account_resources=self.account_resources,
                )
                if service_resources_resolver is None:
                    continue

                target_policy_node = TargetPolicyNode(
                    path_element_type=AwsPtrpPathNodeType.RESOURCE_POLICY,
                    path_arn=service_resource.get_resource_arn(),
                    path_name=service_resource.get_resource_name(),
                    policy_document=service_resource_policy,
                    is_resource_based_policy=True,
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
            assert isinstance(iam_user, PrincipalNodeBase)
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

                assert isinstance(iam_group, PathPrincipalPoliciesNodeBase)
                identity_policies_node = PathPrincipalPoliciesNode(path_principal_policies_base=iam_group, note="")
                self.graph.add_edge(iam_user, identity_policies_node)
                self._insert_attached_policies_and_inline_policies(
                    node_connect_to_target=identity_policies_node,
                    attached_policies_arn=iam_group.get_attached_policies_arn(),
                    inline_policies_and_names=iam_group.get_inline_policies_and_names(),
                    identity_principal_for_resolver=iam_user.identity_principal,
                )

    def build(self) -> 'PtrpAllowedLines':
        self.logger.info("Building the Permissions resolver graph")
        self.graph.add_node(START_NODE)
        self.graph.add_node(END_NODE)

        self._insert_resource_based_policies()

        self._insert_iam_roles_and_trusted_entities()

        self._insert_iam_users_and_iam_groups()

        self.logger.info("Finish to build the iam graph: %s", self.graph)

        return PtrpAllowedLines(graph=self.graph)
