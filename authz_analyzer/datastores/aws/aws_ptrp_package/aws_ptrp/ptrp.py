from dataclasses import dataclass
from logging import Logger
from typing import Callable, Dict, List, Optional, Set

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.iam_entities import IAMAccountEntities, IAMEntities
from aws_ptrp.principals.aws_principals import AwsPrincipals
from aws_ptrp.ptrp_allowed_lines.allowed_line import PtrpAllowedLine
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import PrincipalNodeBase
from aws_ptrp.ptrp_allowed_lines.allowed_lines_resolver import PtrpAllowedLines, PtrpAllowedLinesBuilder
from aws_ptrp.ptrp_allowed_lines.allowed_lines_resolver_result import PtrpAllowedLinesResolverResult
from aws_ptrp.ptrp_models.ptrp_model import (
    AwsPrincipal,
    AwsPtrpActionPermissionLevel,
    AwsPtrpLine,
    AwsPtrpPathNode,
    AwsPtrpResource,
)
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import ServiceActionBase, ServiceActionType, ServiceResourceBase, ServiceResourceType
from aws_ptrp.services.assume_role.assume_role_service import AssumeRoleService
from aws_ptrp.services.federated_user.federated_user_service import FederatedUserService
from aws_ptrp.utils.create_session import create_session_with_assume_role
from boto3 import Session
from serde import field, serde


@serde
@dataclass
class AwsPtrp:
    iam_entities: IAMEntities
    target_account_resources: AwsAccountResources
    aws_actions: AwsActions = field(skip=True)
    aws_principals: AwsPrincipals = field(skip=True)

    @classmethod
    def load_from_role(
        cls,
        logger: Logger,
        role_name: str,
        external_id: Optional[str],
        resource_service_types_to_load: Set[ServiceResourceType],
        target_account_id: str,
        additional_account_ids: Optional[Set[str]] = None,
    ):
        iam_entities_for_accounts: Dict[str, IAMAccountEntities] = {}
        if additional_account_ids:
            if target_account_id in additional_account_ids:
                additional_account_ids.remove(target_account_id)

            for additional_account_id in additional_account_ids:
                session: Session = create_session_with_assume_role(additional_account_id, role_name, external_id)
                logger.info(
                    "Successfully assume the role %s (external id: %s) for additional account id %s",
                    role_name,
                    external_id,
                    additional_account_id,
                )
                iam_entities_for_account = IAMAccountEntities.load_for_account(logger, additional_account_id, session)
                iam_entities_for_accounts[additional_account_id] = iam_entities_for_account

        return cls._load_for_target_account(
            logger,
            role_name,
            external_id,
            target_account_id,
            iam_entities_for_accounts,
            resource_service_types_to_load,
        )

    @classmethod
    def _load_for_target_account(
        cls,
        logger: Logger,
        role_name: str,
        external_id: Optional[str],
        target_account_id: str,
        iam_entities_for_accounts: Dict[str, IAMAccountEntities],
        resource_service_types_to_load: Set[ServiceResourceType],
    ) -> 'AwsPtrp':
        # update the iam_entities from the target account
        target_session: Session = create_session_with_assume_role(target_account_id, role_name, external_id)
        logger.info("Successfully assume the role %s for target account id %s", role_name, target_account_id)
        iam_entities_target_account = IAMAccountEntities.load_for_account(logger, target_account_id, target_session)
        iam_entities_for_accounts[target_account_id] = iam_entities_target_account

        # aws actions
        resource_service_types_to_load.add(AssumeRoleService())  # out of the box resource
        resource_service_types_to_load.add(FederatedUserService())  # out of the box resource
        action_service_types_to_load: Set[ServiceActionType] = set(
            [x for x in resource_service_types_to_load if isinstance(x, ServiceActionType)]
        )
        aws_actions = AwsActions.load(logger, action_service_types_to_load)

        iam_entities = IAMEntities.load(iam_accounts_entities=iam_entities_for_accounts)
        # target account resources
        account_resources = AwsAccountResources.load_services_from_session(
            logger, target_account_id, target_session, resource_service_types_to_load
        )
        account_resources.update_services_from_iam_entities(logger, iam_entities, resource_service_types_to_load)

        # aws principals
        aws_principals = AwsPrincipals.load(logger, iam_entities, account_resources)

        return cls(
            aws_actions=aws_actions,
            aws_principals=aws_principals,
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
            action_permissions.sort()

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
        allowed_lines_resolver_result: PtrpAllowedLinesResolverResult,
    ):
        nodes_notes = allowed_lines_resolver_result.nodes_notes
        service_resources_resolver = allowed_lines_resolver_result.target_resolver
        resource: AwsPtrpResource = line.resource_node.get_ptrp_resource_to_report(nodes_notes)
        path_nodes: List[AwsPtrpPathNode] = line.get_ptrp_path_nodes_to_report(nodes_notes)
        principal_to_report: AwsPrincipal = line.principal_node.get_principal_to_report(nodes_notes)
        principal_to_policy_evaluation: PrincipalNodeBase = line.get_principal_makes_the_request_to_resource()
        service_resource: ServiceResourceBase = line.resource_node.base

        resolved_actions: Optional[
            Set[ServiceActionBase]
        ] = service_resources_resolver.get_resolved_actions_per_resource_and_principal(
            service_resource, principal_to_policy_evaluation.get_stmt_principal()
        )
        if resolved_actions:
            self._cb_line_for_permissions_level(resolved_actions, principal_to_report, resource, path_nodes, cb_line)

    def resolve_permissions(self, logger: Logger, cb_line: Callable[[AwsPtrpLine], None]):
        allowed_lines: PtrpAllowedLines = PtrpAllowedLinesBuilder(
            logger, self.iam_entities, self.aws_actions, self.aws_principals, self.target_account_resources
        ).build()

        for line in allowed_lines.yield_principal_to_resource_lines():
            logger.debug("%s", line)
            allowed_lines_resolver: Optional[PtrpAllowedLinesResolverResult] = PtrpAllowedLinesResolverResult.resolve(
                logger=logger,
                iam_entities=self.iam_entities,
                aws_actions=self.aws_actions,
                aws_principals=self.aws_principals,
                target_account_resources=self.target_account_resources,
                line=line,
            )
            if not allowed_lines_resolver:
                continue
            self._run_cb_line_resolved_permissions(logger, cb_line, line, allowed_lines_resolver)
