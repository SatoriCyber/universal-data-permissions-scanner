from logging import Logger
from typing import Dict, List, Optional, Set, Union

from authz_analyzer.datastores.aws.actions.account_actions import AwsAccountActions
from authz_analyzer.datastores.aws.services.service_base import (
    ServiceActionBase,
    ServiceActionsResolverBase,
    ServiceType,
)


class ActionsResolver:
    # def subtraction(self, other: 'ResolvedResources'):
    #     for resolved_resource in self.resolved_actions:

    # def is_empty(self, type: ResourceType) -> bool:
    #     pass

    @staticmethod
    def _get_stmt_action_regexes_per_service_type(
        _logger: Logger,
        stmt_action_regexes: List[str],
        allow_types_to_resolve: Set[ServiceType],
    ) -> Dict[ServiceType, List[str]]:
        ret: Dict[ServiceType, List[str]] = dict()
        for stmt_action_regex in stmt_action_regexes:
            for service_type in allow_types_to_resolve:
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
        stmt_action_regexes: Union[str, List[str]],
        account_actions: AwsAccountActions,
        allow_types_to_resolve: Set[ServiceType],
    ) -> Optional[Dict[ServiceType, ServiceActionsResolverBase]]:
        services_action_resolver: Dict[ServiceType, ServiceActionsResolverBase] = dict()

        if isinstance(stmt_action_regexes, str):
            stmt_action_regexes = [stmt_action_regexes]

        ret: Dict[ServiceType, List[str]] = ActionsResolver._get_stmt_action_regexes_per_service_type(
            logger, stmt_action_regexes, allow_types_to_resolve
        )
        for service_type, service_regexes in ret.items():
            service_actions: Optional[List[ServiceActionBase]] = account_actions.account_actions.get(service_type)
            if service_actions:
                service_action_resolver: ServiceActionsResolverBase = service_type.load_resolver_service_actions(
                    logger, service_regexes, service_actions
                )
                if not service_action_resolver.is_empty():
                    services_action_resolver[service_type] = service_action_resolver

        return services_action_resolver if services_action_resolver else None