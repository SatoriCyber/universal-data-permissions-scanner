from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Tuple, Callable

from boto3 import Session
from serde import serde

from aws_ptrp.actions.account_actions import AwsAccountActions
from aws_ptrp.policy_evaluation import PolicyEvaluation
from aws_ptrp.permissions_resolver.principal_to_resource_nodes_base import (
    PrincipalPoliciesNodeBase,
    ResourceNodeBase,
)
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.permissions_resolver.permissions_resolver import (
    PermissionsResolverBuilder,
    PermissionsResolver,
)
from aws_ptrp.utils.create_session import create_session_with_assume_role
from aws_ptrp.permissions_resolver.principal_to_resource_line import PrincipalToResourceLine
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.principals import Principal
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services.assume_role.assume_role_service import AssumeRoleService
from aws_ptrp.services import (
    ServiceActionType,
    ServiceActionBase,
    ServiceResourcesResolverBase,
    ServiceResourceType,
)
from aws_ptrp.ptrp_models.ptrp_model import (
    AwsPtrpPathNode,
    AwsPtrpResource,
    AwsPrincipal,
    AwsPtrpActionPermissionLevel,
    AwsPtrpLine,
)


@serde
@dataclass
class AwsPtrp:
    account_actions: AwsAccountActions
    account_resources: AwsAccountResources
    iam_entities: IAMEntities

    @classmethod
    def load_from_role(
        cls,
        logger: Logger,
        aws_account_id: str,
        role_name: str,
        resource_service_types_to_load: Set[ServiceResourceType],
    ):

        session: Session = create_session_with_assume_role(aws_account_id, role_name)
        logger.info("Successfully assume the role %s for account id %s", role_name, aws_account_id)
        return cls.load(logger, session, aws_account_id, resource_service_types_to_load)

    @classmethod
    def load(
        cls,
        logger: Logger,
        session: Session,
        aws_account_id: str,
        resource_service_types_to_load: Set[ServiceResourceType],
    ):
        resource_service_types_to_load.add(AssumeRoleService())  # out of the box resource
        action_service_types_to_load: Set[ServiceActionType] = set(
            [x for x in resource_service_types_to_load if isinstance(x, ServiceActionType)]
        )
        iam_entities: IAMEntities = IAMEntities.load(logger, aws_account_id, session)
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

    def _cb_line_for_permissions_level(
        self,
        actions: Set[ServiceActionBase],
        principal: AwsPrincipal,
        resource: AwsPtrpResource,
        path_nodes: List[AwsPtrpPathNode],
        cb_line: Callable[[AwsPtrpLine], None],
    ):
        for permissions_level in AwsPtrpActionPermissionLevel:
            action_permissions: List[str] = [
                action.get_action_name()
                for action in actions
                if action.get_action_permission_level() == permissions_level
            ]

            if action_permissions:
                cb_line(
                    AwsPtrpLine(
                        resource=resource,
                        path_nodes=path_nodes,
                        principal=principal,
                        action_permission_level=AwsPtrpActionPermissionLevel.WRITE,
                        action_permissions=action_permissions,
                    )
                )

    def _run_cb_line_resolved_permissions(
        self,
        _logger: Logger,
        cb_line: Callable[[AwsPtrpLine], None],
        line: PrincipalToResourceLine,
        service_resources_resolver: Dict[ServiceResourceType, ServiceResourcesResolverBase],
    ):
        resource: AwsPtrpResource = line.get_ptrp_resource_to_report()
        path_nodes: List[AwsPtrpPathNode] = line.get_ptrp_path_nodes_to_report()
        principal_to_report: AwsPrincipal = line.get_principal_to_report()
        principal_to_policy_evaluation: Principal = line.get_principal_to_policy_evaluation()
        service_resource = line.resource_node

        for _service_type, service_resolver in service_resources_resolver.items():
            actions: Optional[Set[ServiceActionBase]] = service_resolver.get_resolved_actions(
                service_resource, principal_to_policy_evaluation
            )
            if actions:
                self._cb_line_for_permissions_level(actions, principal_to_report, resource, path_nodes, cb_line)

    def _resolve_principal_to_resource_line_permissions(
        self,
        logger: Logger,
        line: PrincipalToResourceLine,
    ) -> Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]:

        target_policy: PolicyDocument = line.target_policy_node.policy_document
        resource_node: ResourceNodeBase = line.resource_node
        principal_to_policy: Principal = line.get_principal_to_policy_evaluation()
        principal_policies_base: PrincipalPoliciesNodeBase = line.get_principal_policies_base_to_policy_evaluation()
        principal_policies: List[PolicyDocument] = list(
            map(
                lambda arn: self.iam_entities.iam_policies[arn].policy_document,
                principal_policies_base.get_attached_policies_arn(),
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

        return PolicyEvaluation.run(
            logger=logger,
            account_actions=self.account_actions,
            account_resources=self.account_resources,
            identity_principal=principal_to_policy,
            parent_resource_arn=None,
            target_policy=target_policy,
            identity_policies=principal_policies,
            resource_policy=resource_node.get_resource_policy(),
        )

    def resolve_permissions(self, logger: Logger, cb_line: Callable[[AwsPtrpLine], None]):
        permissions_resolver: PermissionsResolver = PermissionsResolverBuilder(
            logger, self.iam_entities, self.account_actions, self.account_resources
        ).build()

        for line in permissions_resolver.yield_principal_to_resource_lines():  # type: PrincipalToResourceLine
            logger.info("%s", line)
            service_resources_resolver: Optional[
                Dict[ServiceResourceType, ServiceResourcesResolverBase]
            ] = self._resolve_principal_to_resource_line_permissions(logger, line)
            if not service_resources_resolver:
                continue
            self._run_cb_line_resolved_permissions(logger, cb_line, line, service_resources_resolver)
