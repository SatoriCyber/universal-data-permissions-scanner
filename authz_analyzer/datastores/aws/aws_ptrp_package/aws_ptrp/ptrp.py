from dataclasses import dataclass
from logging import Logger
from typing import Callable, Dict, List, Optional, Set, Tuple

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.iam.policy.policy_document import PolicyDocument
from aws_ptrp.policy_evaluation import PolicyEvaluation
from aws_ptrp.principals import Principal
from aws_ptrp.ptrp_allowed_lines.allowed_line import PtrpAllowedLine
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import PoliciesNodeBase, ResourceNode
from aws_ptrp.ptrp_allowed_lines.allowed_lines_resolver import PtrpAllowedLines, PtrpAllowedLinesBuilder
from aws_ptrp.ptrp_models.ptrp_model import (
    AwsPrincipal,
    AwsPtrpActionPermissionLevel,
    AwsPtrpLine,
    AwsPtrpPathNode,
    AwsPtrpResource,
)
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import (
    ServiceActionBase,
    ServiceActionType,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
    ServiceResourceType,
)
from aws_ptrp.services.assume_role.assume_role_service import AssumeRoleService
from aws_ptrp.services.federated_user.federated_user_service import FederatedUserService
from aws_ptrp.utils.create_session import create_session_with_assume_role
from boto3 import Session
from serde import serde


@serde
@dataclass
class AwsPtrp:
    aws_actions: AwsActions
    iam_entities: IAMEntities
    target_account_resources: AwsAccountResources

    @classmethod
    def load_from_role(
        cls,
        logger: Logger,
        role_name: str,
        resource_service_types_to_load: Set[ServiceResourceType],
        target_account_id: str,
        additional_account_ids: Optional[Set[str]] = None,
    ):
        if additional_account_ids:
            if target_account_id in additional_account_ids:
                additional_account_ids.remove(target_account_id)
            iam_entities: IAMEntities = cls._load_iam_entities_for_additional_account(
                logger, role_name, additional_account_ids
            )
        else:
            iam_entities = IAMEntities()
        return cls._load_for_target_account(
            logger, role_name, target_account_id, iam_entities, resource_service_types_to_load
        )

    @classmethod
    def _load_iam_entities_for_additional_account(
        cls, logger: Logger, role_name: str, additional_account_ids: Set[str]
    ) -> IAMEntities:
        iam_entities = IAMEntities()
        for additional_account_id in additional_account_ids:
            session: Session = create_session_with_assume_role(additional_account_id, role_name)
            logger.info(
                "Successfully assume the role %s for additional account id %s", role_name, additional_account_id
            )
            iam_entities.update_for_account(logger, additional_account_id, session)
        return iam_entities

    @classmethod
    def _load_for_target_account(
        cls,
        logger: Logger,
        role_name: str,
        target_account_id: str,
        iam_entities: IAMEntities,
        resource_service_types_to_load: Set[ServiceResourceType],
    ) -> 'AwsPtrp':
        # update the iam_entities from the target account
        target_session: Session = create_session_with_assume_role(target_account_id, role_name)
        logger.info("Successfully assume the role %s for target account id %s", role_name, target_account_id)
        iam_entities.update_for_account(logger, target_account_id, target_session)

        # aws actions
        resource_service_types_to_load.add(AssumeRoleService())  # out of the box resource
        resource_service_types_to_load.add(FederatedUserService())  # out of the box resource
        action_service_types_to_load: Set[ServiceActionType] = set(
            [x for x in resource_service_types_to_load if isinstance(x, ServiceActionType)]
        )
        aws_actions = AwsActions.load(logger, action_service_types_to_load)

        # target account resources
        account_resources = AwsAccountResources.load(
            logger, target_account_id, iam_entities, target_session, resource_service_types_to_load
        )
        return cls(
            aws_actions=aws_actions,
            target_account_resources=account_resources,
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
                        action_permission_level=permissions_level,
                        action_permissions=action_permissions,
                    )
                )

    def _run_cb_line_resolved_permissions(
        self,
        _logger: Logger,
        cb_line: Callable[[AwsPtrpLine], None],
        line: PtrpAllowedLine,
        service_resources_resolver: Dict[ServiceResourceType, ServiceResourcesResolverBase],
    ):
        resource: AwsPtrpResource = line.get_ptrp_resource_to_report()
        path_nodes: List[AwsPtrpPathNode] = line.get_ptrp_path_nodes_to_report()
        principal_to_report: AwsPrincipal = line.get_principal_to_report()
        principal_to_policy_evaluation: Principal = line.get_principal_to_policy_evaluation()
        service_resource: ServiceResourceBase = line.resource_node.base

        for _service_type, service_resolver in service_resources_resolver.items():
            actions: Optional[
                Set[ServiceActionBase]
            ] = service_resolver.get_resolved_actions_per_resource_and_principal(
                service_resource, principal_to_policy_evaluation
            )
            if actions:
                self._cb_line_for_permissions_level(actions, principal_to_report, resource, path_nodes, cb_line)

    def _resolve_principal_to_resource_line_permissions(
        self,
        logger: Logger,
        line: PtrpAllowedLine,
    ) -> Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]:

        target_policy: PolicyDocument = line.target_policy_node.policy_document
        is_target_policy_resource_based: bool = line.target_policy_node.is_resource_based_policy
        resource_node: ResourceNode = line.resource_node
        principal_to_policy: Principal = line.get_principal_to_policy_evaluation()
        # Extract all principal policies (inline & attached)
        principal_policies: List[PolicyDocument] = []
        principal_policies_bases: List[PoliciesNodeBase] = line.get_principal_policies_base_to_policy_evaluation()
        for principal_policies_base in principal_policies_bases:
            principal_policies.extend(
                list(
                    map(
                        lambda arn: self.iam_entities.iam_policies[arn].policy_document,
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

        return PolicyEvaluation.run(
            logger=logger,
            aws_actions=self.aws_actions,
            account_resources=self.target_account_resources,
            identity_principal=principal_to_policy,
            target_policy=target_policy,
            is_target_policy_resource_based=is_target_policy_resource_based,
            service_resource=resource_node.base,
            service_resource_type=resource_node.service_resource_type,
            identity_policies=principal_policies,
        )

    def resolve_permissions(self, logger: Logger, cb_line: Callable[[AwsPtrpLine], None]):
        allowed_lines_resolver: PtrpAllowedLines = PtrpAllowedLinesBuilder(
            logger, self.iam_entities, self.aws_actions, self.target_account_resources
        ).build()

        for line in allowed_lines_resolver.yield_principal_to_resource_lines():  # type: PtrpAllowedLine
            logger.info("%s", line)
            service_resources_resolver: Optional[
                Dict[ServiceResourceType, ServiceResourcesResolverBase]
            ] = self._resolve_principal_to_resource_line_permissions(logger, line)
            if not service_resources_resolver:
                continue
            self._run_cb_line_resolved_permissions(logger, cb_line, line, service_resources_resolver)
