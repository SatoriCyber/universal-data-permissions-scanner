from typing import Dict, Any, Optional, Type, List, Union, Tuple, AnyStr, Set
from dataclasses import dataclass
from logging import Logger
from authz_analyzer.datastores.aws.services.service_base import ServiceType
from authz_analyzer.datastores.aws.actions.service_actions_resolver_base import ServiceActionsResolverBase
from authz_analyzer.datastores.aws.actions.account_actions import AwsAccountActions


@dataclass
class ActionsResolverHandler:
    resolved_actions: Dict[ServiceType, ServiceActionsResolverBase]

    # def subtraction(self, other: 'ResolvedResources'):
    #     for resolved_resource in self.resolved_actions:

    # def is_empty(self, type: ResourceType) -> bool:
    #     pass

    @staticmethod
    def resolve_stmt_action_regex(
        logger: Logger,
        stmt_action_regex: str,
        account_actions: AwsAccountActions,
        allow_types_to_resolve: Set[ServiceType],
    ) -> Dict[ServiceType, ServiceActionsResolverBase]:
        ret: Dict[ServiceType, ServiceActionsResolverBase] = dict()
        for service_type, service_actions in account_actions.account_actions.items():
            if stmt_action_regex != "*" or service_type not in allow_types_to_resolve:
                continue

            service_prefix = service_type.get_action_service_prefix()
            stmt_relative_id_regex = (
                "*"
                if stmt_action_regex == "*"
                else stmt_action_regex[len(service_prefix):]
                if stmt_action_regex.startswith(service_prefix)
                else None
            )
            if stmt_relative_id_regex is None:
                continue

            resolved_service_actions: ServiceActionsResolverBase = service_type.load_resolver_service_actions(
                logger, stmt_relative_id_regex, service_actions
            )
            ret[service_type] = resolved_service_actions

        return ret

    @classmethod
    def load_from_stmt_action_regexes(
        cls,
        logger: Logger,
        stmt_action_regexes: Union[str, List[str]],
        account_actions: AwsAccountActions,
        allow_types_to_resolve: Set[ServiceType],
    ) -> 'ActionsResolverHandler':
        resolved_actions: Dict[ServiceType, ServiceActionsResolverBase] = dict()
        if isinstance(stmt_action_regexes, str):
            stmt_action_regexes = [stmt_action_regexes]

        for stmt_action_regex in stmt_action_regexes:
            ret: Dict[ServiceType, ServiceActionsResolverBase] = ActionsResolverHandler.resolve_stmt_action_regex(
                logger, stmt_action_regex, account_actions, allow_types_to_resolve
            )
            for service_type, resolved_service_actions in ret.items():
                curr_resolved_service_actions: Optional[ServiceActionsResolverBase] = resolved_actions.get(
                    service_type, None
                )
                if curr_resolved_service_actions is not None:
                    curr_resolved_service_actions.merge(resolved_service_actions)
                else:
                    resolved_actions[service_type] = resolved_service_actions

        return cls(resolved_actions=resolved_actions)
