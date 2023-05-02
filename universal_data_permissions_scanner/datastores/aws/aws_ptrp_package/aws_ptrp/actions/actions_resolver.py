from logging import Logger
from typing import Dict, List, Optional, Set

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.services import ServiceActionBase, ServiceActionsResolverBase, ServiceActionType


class ActionsResolver:
    @staticmethod
    def _get_stmt_action_regexes_per_service_type(
        _logger: Logger,
        stmt_action_regexes: List[str],
        service_types_to_resolve: Set[ServiceActionType],
    ) -> Dict[ServiceActionType, List[str]]:
        ret: Dict[ServiceActionType, List[str]] = dict()
        for stmt_action_regex in stmt_action_regexes:
            for service_type in service_types_to_resolve:
                service_prefix = service_type.get_action_service_prefix()
                stmt_relative_id_regex = (
                    "*"
                    if stmt_action_regex == "*"
                    else stmt_action_regex[len(service_prefix) :]
                    if stmt_action_regex.startswith(service_prefix)
                    else None
                )
                if stmt_relative_id_regex is None:
                    continue

                regexes_list: Optional[List[str]] = ret.get(service_type, None)
                if regexes_list:
                    regexes_list.append(stmt_relative_id_regex)
                else:
                    ret[service_type] = [stmt_relative_id_regex]

        return ret

    @classmethod
    def resolve_stmt_action_regexes(
        cls,
        logger: Logger,
        stmt_action_regexes: List[str],
        not_action_annotated: bool,
        aws_actions: AwsActions,
        allowed_service_action_types: Optional[Set[ServiceActionType]] = None,
    ) -> Optional[Dict[ServiceActionType, ServiceActionsResolverBase]]:
        services_action_resolver: Dict[ServiceActionType, ServiceActionsResolverBase] = dict()

        if isinstance(stmt_action_regexes, str):
            stmt_action_regexes = [stmt_action_regexes]

        service_types_to_resolve: Set[ServiceActionType] = set(aws_actions.aws_actions.keys())
        if allowed_service_action_types:
            service_types_to_resolve.intersection(allowed_service_action_types)
        ret: Dict[ServiceActionType, List[str]] = ActionsResolver._get_stmt_action_regexes_per_service_type(
            logger, stmt_action_regexes, service_types_to_resolve
        )
        for service_type, service_regexes in ret.items():
            service_actions: Optional[Set[ServiceActionBase]] = aws_actions.aws_actions.get(service_type)
            if service_actions:
                service_action_resolver: ServiceActionsResolverBase = (
                    service_type.load_resolver_service_actions_from_single_stmt(
                        logger, service_regexes, service_actions, not_action_annotated
                    )
                )
                if not service_action_resolver.is_empty():
                    services_action_resolver[service_type] = service_action_resolver

        return services_action_resolver if services_action_resolver else None
