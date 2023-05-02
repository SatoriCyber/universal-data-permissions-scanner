from dataclasses import dataclass
from logging import Logger
from typing import Any, Dict, List, Optional, Set, Type

from aws_ptrp.services import (
    ServiceActionBase,
    ServiceActionType,
    get_service_action_by_name,
    get_service_action_type_by_name,
)
from serde import field, from_dict, serde, to_dict


def to_dict_serializer(aws_actions: Dict[ServiceActionType, List[ServiceActionBase]]) -> Dict[str, List[Any]]:
    return dict([(k.get_service_name(), to_dict(v)) for (k, v) in aws_actions.items()])


def from_dict_deserializer(
    account_actions_from_deserializer: Dict[str, List[Any]]
) -> Dict[ServiceActionType, List[ServiceActionBase]]:
    aws_actions: Dict[ServiceActionType, List[ServiceActionBase]] = dict()
    for service_key_name, service_actions_base in account_actions_from_deserializer.items():
        service_type: Optional[Type[ServiceActionType]] = get_service_action_type_by_name(service_key_name)
        service_action: Optional[Type[ServiceActionBase]] = get_service_action_by_name(service_key_name)
        if service_type and service_action:
            value: List[ServiceActionBase] = [
                from_dict(service_action, service_action_base_dict) for service_action_base_dict in service_actions_base
            ]  # type: ignore
            aws_actions[service_type()] = value

    return aws_actions


@serde
@dataclass
class AwsActions:
    aws_actions: Dict[ServiceActionType, Set[ServiceActionBase]] = field(
        serializer=to_dict_serializer, deserializer=from_dict_deserializer
    )

    @classmethod
    def load(cls, logger: Logger, service_types_to_load: Set[ServiceActionType]):
        logger.info(f"Init AwsActions {service_types_to_load}...")
        aws_actions: Dict[ServiceActionType, Set[ServiceActionBase]] = dict()
        for service_type_to_load in service_types_to_load:
            ret: Set[ServiceActionBase] = service_type_to_load.load_service_actions(logger)
            aws_actions[service_type_to_load] = ret

        return cls(aws_actions=aws_actions)
