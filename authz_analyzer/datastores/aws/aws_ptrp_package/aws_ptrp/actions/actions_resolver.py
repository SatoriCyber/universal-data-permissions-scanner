from logging import Logger
from typing import Dict, List, Optional, Set, Union

from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.services import ServiceActionBase, ServiceActionsResolverBase, ServiceActionType
from aws_ptrp.utils.regex_subset import is_aws_regex_full_subset


class ActionsResolver:
    @staticmethod
    def _get_stmt_action_regexes_per_service_type(
        logger: Logger,
        stmt_action_regexes: List[str],
        not_action_annotated: bool,
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

        if not_action_annotated:
            # if NotAction is used, we need to include the actions which are not in ret[service_type] for each service_type
            for service_type in service_types_to_resolve:
                service_actions: List[ServiceActionBase] = service_type.load_service_actions(logger)
                included_service_actions: Set[ServiceActionBase] = set()
                if service_type not in ret:
                    # if the service_type is not in ret, then all the service_actions should be included
                    included_service_actions = set(service_actions)
                else:
                    for action in ret[service_type]:
                        current_action_complement_set: Set[ServiceActionBase] = set()
                        for service_action in service_actions:
                            # if the service_action is a full-subset of the action, then we don't need to include it
                            # e.g. action = "s3:Get*" and service_action = "s3:GetObject"
                            if is_aws_regex_full_subset(action, service_action.get_action_name()):
                                continue
                            # Add the service action to the set of actions to be included
                            current_action_complement_set.add(service_action)

                        # Note that we might encounter a case where the action_1 and action_2 partially complements each other
                        # e.g. action_1 = "s3:Delete*" and action_2 = "s3:Get*"
                        # And therefore using intersection_update will result in s3:* - (s3:Delete* + s3:Get*)
                        if included_service_actions:
                            included_service_actions.intersection_update(current_action_complement_set)
                        else:
                            included_service_actions = current_action_complement_set

                ret[service_type] = list(map(lambda action: action.get_action_name(), included_service_actions))

        return ret

    @classmethod
    def resolve_stmt_action_regexes(
        cls,
        logger: Logger,
        stmt_action_regexes: Union[str, List[str]],
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
            logger, stmt_action_regexes, not_action_annotated, service_types_to_resolve
        )
        for service_type, service_regexes in ret.items():
            service_actions: Optional[List[ServiceActionBase]] = aws_actions.aws_actions.get(service_type)
            if service_actions:
                service_action_resolver: ServiceActionsResolverBase = (
                    service_type.load_resolver_service_actions_from_single_stmt(
                        logger, service_regexes, service_actions
                    )
                )
                if not service_action_resolver.is_empty():
                    services_action_resolver[service_type] = service_action_resolver

        return services_action_resolver if services_action_resolver else None
