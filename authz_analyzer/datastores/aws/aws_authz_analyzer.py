from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Tuple, Union

import networkx as nx
from boto3 import Session
from serde import serde

from authz_analyzer.datastores.aws.actions.account_actions import AwsAccountActions
from authz_analyzer.datastores.aws.iam.iam_entities import IAMEntities
from authz_analyzer.datastores.aws.iam.iam_groups import IAMGroup
from authz_analyzer.datastores.aws.iam.iam_policies import IAMPolicy
from authz_analyzer.datastores.aws.iam.iam_roles import IAMRole
from authz_analyzer.datastores.aws.iam.iam_users import IAMUser
from authz_analyzer.datastores.aws.iam.policy.policy_document import Effect, PolicyDocument, PolicyDocumentGetterBase
from authz_analyzer.datastores.aws.iam.policy.principal import StmtPrincipal
from authz_analyzer.datastores.aws.resources.account_resources import AwsAccountResources
from authz_analyzer.datastores.aws.services import (
    ServiceActionType,
    ServiceResourcesResolverBase,
    ServiceResourceType,
)
from authz_analyzer.models.model import (
    Asset,
    AuthzEntry,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)
from authz_analyzer.writers.base_writers import BaseWriter


@serde
@dataclass
class AwsAuthzAnalyzer:
    account_actions: AwsAccountActions
    account_resources: AwsAccountResources
    iam_entities: IAMEntities

    @classmethod
    def load(
        cls,
        logger: Logger,
        iam_entities: IAMEntities,
        session: Session,
        service_types_to_load: Set[Union[ServiceResourceType, ServiceActionType]],
    ):
        action_service_types_to_load: Set[ServiceActionType] = set(
            [x for x in service_types_to_load if isinstance(x, ServiceActionType)]
        )
        resource_service_types_to_load: Set[ServiceResourceType] = set(
            [x for x in service_types_to_load if isinstance(x, ServiceResourceType)]
        )
        aws_account_id = iam_entities.account_id
        account_actions = AwsAccountActions.load(logger, aws_account_id, action_service_types_to_load)
        account_resources = AwsAccountResources.load(logger, aws_account_id, session, resource_service_types_to_load)
        return cls(
            account_actions=account_actions,
            account_resources=account_resources,
            iam_entities=iam_entities,
        )

    def write_permissions_for_assets(
        self,
        logger: Logger,
        writer: BaseWriter,
        identity: Identity,
        path: List[AuthzPathElement],
        policy_document: PolicyDocument,
        parent_arn: str,
    ):
        service_resources_resolver: Optional[
            Dict[ServiceResourceType, ServiceResourcesResolverBase]
        ] = policy_document.get_services_resources_resolver(
            logger,
            parent_arn,
            self.account_actions,
            self.account_resources,
            Effect.Allow,
        )

        if not service_resources_resolver:
            return

        for _service_type, service_resolver in service_resources_resolver.items():
            for resource, actions in service_resolver.yield_resolved_resource_with_actions():
                asset = Asset(name=resource.get_resource_name(), type=resource.get_asset_type())
                if any(action.get_action_permission_level() == PermissionLevel.WRITE for action in actions):
                    writer.write_entry(
                        AuthzEntry(asset=asset, path=path, identity=identity, permission=PermissionLevel.WRITE)
                    )
                if any(action.get_action_permission_level() == PermissionLevel.READ for action in actions):
                    writer.write_entry(
                        AuthzEntry(asset=asset, path=path, identity=identity, permission=PermissionLevel.READ)
                    )
                if any(action.get_action_permission_level() == PermissionLevel.FULL for action in actions):
                    writer.write_entry(
                        AuthzEntry(asset=asset, path=path, identity=identity, permission=PermissionLevel.FULL)
                    )

    def write_permissions(self, logger: Logger, writer: BaseWriter):
        principal_graph: nx.DiGraph = self.iam_entities.build_principal_network_graph(logger, self.account_actions)
        for iam_user_path in nx.all_simple_paths(principal_graph, source="START_NODE", target="END_NODE"):
            logger.info("%s", iam_user_path)

            # Get the Identity from the first node
            identity: Optional[Identity] = None
            identity_node = iam_user_path[1]
            if isinstance(identity_node, IAMUser):
                identity = Identity(
                    id=identity_node.arn.get_arn(), type=IdentityType.IAM_USER, name=identity_node.user_name
                )
            elif isinstance(identity_node, IAMRole):
                identity = Identity(id=identity_node.arn, type=IdentityType.IAM_ROLE, name=identity_node.role_name)
            elif isinstance(identity_node, StmtPrincipal):
                identity_type = identity_node.principal_type.to_identity_type()
                identity = Identity(id=identity_node.get_arn(), type=identity_type, name=identity_node.get_name())
            else:
                raise BaseException(
                    f"Invalid type of 'Identity' node {type(identity_node)} In {iam_user_path}, valid types are IAMUser, IAMRole"
                )

            # Get the path of AuthzPathElement
            path: List[AuthzPathElement] = []
            for node in iam_user_path[2:-1]:
                if isinstance(node, IAMRole):
                    path.append(
                        AuthzPathElement(
                            id=node.arn,
                            name=node.role_name,
                            type=AuthzPathElementType.IAM_ROLE,
                            note="",
                        )
                    )
                elif isinstance(node, IAMPolicy):
                    path.append(
                        AuthzPathElement(
                            id=node.policy.arn,
                            name=node.policy.policy_name,
                            type=AuthzPathElementType.IAM_POLICY,
                            note="",
                        )
                    )
                elif isinstance(node, IAMGroup):
                    path.append(
                        AuthzPathElement(
                            id=node.arn,
                            name=node.group_name,
                            type=AuthzPathElementType.IAM_GROUP,
                            note="",
                        )
                    )
                else:
                    raise BaseException(
                        f"Invalid type of 'AuthzPathElement' node {type(node)} in {iam_user_path}, valid types are IAMRole, IAMPolicy, IAMGroup"
                    )

            # For the identity and its path, writes the assets permissions
            node_with_policies_to_resolve = iam_user_path[-2]
            if isinstance(node_with_policies_to_resolve, PolicyDocumentGetterBase):
                policy_documents_and_names: List[
                    Tuple[PolicyDocument, str]
                ] = node_with_policies_to_resolve.inline_policy_documents_and_names
                parent_arn: str = node_with_policies_to_resolve.parent_arn
                for policy_document_and_name in policy_documents_and_names:
                    policy_document: PolicyDocument = policy_document_and_name[0]
                    policy_name: str = policy_document_and_name[1]
                    try:
                        path.append(
                            AuthzPathElement(
                                id=parent_arn,
                                name=policy_name,
                                type=AuthzPathElementType.IAM_INLINE_POLICY,
                                note="",
                            )
                        )
                        self.write_permissions_for_assets(logger, writer, identity, path, policy_document, parent_arn)
                    finally:
                        path.pop()
            elif isinstance(node_with_policies_to_resolve, IAMPolicy):
                policy_document: PolicyDocument = node_with_policies_to_resolve.policy_document  # type: ignore[no-redef]
                parent_arn: str = node_with_policies_to_resolve.policy.arn  # type: ignore[no-redef]
                self.write_permissions_for_assets(logger, writer, identity, path, policy_document, parent_arn)
            else:
                raise BaseException(
                    f"Invalid type of 'Asset' node {type(node_with_policies_to_resolve)} In {iam_user_path}, not instance of PolicyDocumentGetterBase or IAMPolicy"
                )

        writer.close()
