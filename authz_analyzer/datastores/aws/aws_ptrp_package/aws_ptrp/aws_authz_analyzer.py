from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Union, Tuple, Callable

from boto3 import Session
from serde import serde

from aws_ptrp.actions.account_actions import AwsAccountActions
from aws_ptrp.policy_evaluation import PolicyEvaluation
from aws_ptrp.permissions_resolver.identity_to_resource_nodes_base import (
    IdentityPoliciesNodeBase,
    ResourceNodeBase,
)
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.permissions_resolver.permissions_resolver import (
    PermissionsResolverBuilder,
    PermissionsResolver,
)
from aws_ptrp.permissions_resolver.identity_to_resource_line import IdentityToResourceLine
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.iam.policy.principal import StmtPrincipal
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import (
    ServiceActionType,
    ServiceActionBase,
    ServiceResourcesResolverBase,
    ServiceResourceType,
)
from authz_analyzer.models.model import (
    AuthzPathElement,
    Asset,
    AuthzEntry,
    Identity,
    PermissionLevel,
)


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
        account_resources = AwsAccountResources.load(
            logger, aws_account_id, iam_entities, session, resource_service_types_to_load
        )
        return cls(
            account_actions=account_actions,
            account_resources=account_resources,
            iam_entities=iam_entities,
        )

    def _write_resolved_permissions(
        self,
        _logger: Logger,
        cb_authz_entry: Callable[[AuthzEntry], None],
        line: IdentityToResourceLine,
        service_resources_resolver: Dict[ServiceResourceType, ServiceResourcesResolverBase],
    ):

        asset: Asset = line.get_asset_to_report()
        path: List[AuthzPathElement] = line.get_path_elements_to_report()
        identity: Identity = line.get_identity_to_report()
        identity_principal: StmtPrincipal = line.get_identity_principal_to_policy_evaluation()
        service_resource = line.resource_node

        for _service_type, service_resolver in service_resources_resolver.items():
            actions: Optional[Set[ServiceActionBase]] = service_resolver.get_resolved_actions(
                service_resource, identity_principal
            )
            if actions is None:
                continue
            if any(action.get_action_permission_level() == PermissionLevel.WRITE for action in actions):
                cb_authz_entry(AuthzEntry(asset=asset, path=path, identity=identity, permission=PermissionLevel.WRITE))
            if any(action.get_action_permission_level() == PermissionLevel.READ for action in actions):
                cb_authz_entry(AuthzEntry(asset=asset, path=path, identity=identity, permission=PermissionLevel.READ))
            if any(action.get_action_permission_level() == PermissionLevel.FULL for action in actions):
                cb_authz_entry(AuthzEntry(asset=asset, path=path, identity=identity, permission=PermissionLevel.FULL))

    def _resolve_identity_to_resource_line_permissions(
        self,
        logger: Logger,
        line: IdentityToResourceLine,
    ) -> Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]:

        target_policy: PolicyDocument = line.target_policy_node.policy_document
        resource_node: ResourceNodeBase = line.resource_node
        identity_principal: StmtPrincipal = line.get_identity_principal_to_policy_evaluation()
        identity_policies_base: IdentityPoliciesNodeBase = line.get_identity_policies_base_to_policy_evaluation()
        identity_policies: List[PolicyDocument] = list(
            map(
                lambda arn: self.iam_entities.iam_policies[arn].policy_document,
                identity_policies_base.get_attached_policies_arn(),
            )
        )
        inline_policies_and_names: List[
            Tuple[PolicyDocument, str]
        ] = identity_policies_base.get_inline_policies_and_names()
        identity_policies.extend(
            list(
                map(
                    lambda policy_and_name: policy_and_name[0],
                    inline_policies_and_names,
                )
            )
        )

        return PolicyEvaluation.run(
            logger=logger,
            account_actions=self.account_actions,
            account_resources=self.account_resources,
            identity_principal=identity_principal,
            parent_resource_arn=None,
            target_policy=target_policy,
            identity_policies=identity_policies,
            resource_policy=resource_node.get_resource_policy(),
        )

    def resolve_permissions(self, logger: Logger, cb_authz_entry: Callable[[AuthzEntry], None]):
        permissions_resolver: PermissionsResolver = PermissionsResolverBuilder(
            logger, self.iam_entities, self.account_actions, self.account_resources
        ).build()

        for line in permissions_resolver.yield_identity_to_resource_lines():  # type: IdentityToResourceLine
            logger.info("%s", line)
            service_resources_resolver: Optional[
                Dict[ServiceResourceType, ServiceResourcesResolverBase]
            ] = self._resolve_identity_to_resource_line_permissions(logger, line)
            if not service_resources_resolver:
                continue
            self._write_resolved_permissions(logger, cb_authz_entry, line, service_resources_resolver)
