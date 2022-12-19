from typing import Dict, Any, Optional, Type, List, Union, Tuple, AnyStr, Set
from dataclasses import dataclass
from serde import field, serde, to_dict, from_dict
from boto3 import Session
from logging import Logger
from authz_analyzer.datastores.aws.services.service_entity_base import ServiceType, ServiceEntityBase
from authz_analyzer.datastores.aws.services.s3.bucket import S3ServiceType, S3Bucket, S3_SERVICE_NAME


def to_dict_serializer(account_resources: Dict[ServiceType, List[ServiceEntityBase]]) -> Dict[str, List[Any]]:
    return dict([(k.get_service_name(), to_dict(v)) for (k, v) in account_resources.items()])


def from_dict_deserializer(
    account_resources_from_deserializer: Dict[str, List[Any]]
) -> Dict[ServiceType, List[ServiceEntityBase]]:
    account_resources: Dict[ServiceType, List[ServiceEntityBase]] = dict()
    for service_key_name, service_entities_base in account_resources_from_deserializer.items():
        if service_key_name == S3_SERVICE_NAME:
            service_key = S3ServiceType()
            value: List[ServiceEntityBase] = [
                from_dict(S3Bucket, service_entity_base_dict) for service_entity_base_dict in service_entities_base
            ]
            account_resources[service_key] = value

    return account_resources


@serde
@dataclass
class AwsAccountResources:
    account_resources: Dict[ServiceType, List[ServiceEntityBase]] = field(
        serializer=to_dict_serializer, deserializer=from_dict_deserializer
    )

    @classmethod
    def load(cls, logger: Logger, aws_account_id: str, session: Session, service_types_to_load: Set[ServiceType]):
        logger.info(f"Start pulling AWS account {aws_account_id} with resources {service_types_to_load}...")
        account_resources: Dict[ServiceType, List[ServiceEntityBase]] = dict()
        for service_type_to_load in service_types_to_load:
            logger.info(f"Start pulling AWS account resources from type {service_type_to_load.get_service_name()}")
            ret: List[ServiceEntityBase] = service_type_to_load.load_service_entities_from_session(logger, session)
            account_resources[service_type_to_load] = ret

        return cls(account_resources=account_resources)
