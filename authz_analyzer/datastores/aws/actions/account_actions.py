from typing import Dict, Any, Optional, Type, List, Union, Tuple, AnyStr, Set
from dataclasses import dataclass
from logging import Logger
from authz_analyzer.datastores.aws.services.service_base import ServiceType, ServiceActionBase
from authz_analyzer.datastores.aws.services.s3.bucket import S3Bucket
from authz_analyzer.datastores.aws.services.s3.s3_service import S3_SERVICE_NAME, S3ServiceType
from serde import serde, field, to_dict, from_dict


def to_dict_serializer(account_actions: Dict[ServiceType, List[ServiceActionBase]]) -> Dict[str, List[Any]]:
    return dict([(k.get_service_name(), to_dict(v)) for (k, v) in account_actions.items()])


def from_dict_deserializer(
    account_actions_from_deserializer: Dict[str, List[Any]]
) -> Dict[ServiceType, List[ServiceActionBase]]:
    account_actions: Dict[ServiceType, List[ServiceActionBase]] = dict()
    for service_key_name, service_actions_base in account_actions_from_deserializer.items():
        if service_key_name == S3_SERVICE_NAME:
            service_key = S3ServiceType()
            value: List[ServiceActionBase] = [
                from_dict(S3Bucket, service_action_base_dict) for service_action_base_dict in service_actions_base
            ]
            account_actions[service_key] = value

    return account_actions


@serde
@dataclass
class AwsAccountActions:
    account_actions: Dict[ServiceType, List[ServiceActionBase]] = field(
        serializer=to_dict_serializer, deserializer=from_dict_deserializer
    )

    @classmethod
    def load(cls, logger: Logger, aws_account_id: str, service_types_to_load: Set[ServiceType]):
        logger.info(f"Init AWS account {aws_account_id} with actions {service_types_to_load}...")
        account_actions: Dict[ServiceType, List[ServiceActionBase]] = dict()
        for service_type_to_load in service_types_to_load:
            ret: List[ServiceActionBase] = service_type_to_load.load_service_actions(logger)
            account_actions[service_type_to_load] = ret

        return cls(account_actions=account_actions)
