from dataclasses import dataclass
from logging import Logger
from typing import Any, AnyStr, Dict, List, Optional, Set, Tuple, Type, Union

from boto3 import Session
from serde import field, from_dict, serde, to_dict

from authz_analyzer.datastores.aws.services.s3.bucket import S3Bucket
from authz_analyzer.datastores.aws.services.s3.s3_service import S3_SERVICE_NAME, S3ServiceType
from authz_analyzer.datastores.aws.services.service_base import ServiceResourceBase, ServiceType


def to_dict_serializer(account_resources: Dict[ServiceType, List[ServiceResourceBase]]) -> Dict[str, List[Any]]:
    return dict([(k.get_service_name(), to_dict(v)) for (k, v) in account_resources.items()])


def from_dict_deserializer(
    account_resources_from_deserializer: Dict[str, List[Any]]
) -> Dict[ServiceType, List[ServiceResourceBase]]:
    account_resources: Dict[ServiceType, List[ServiceResourceBase]] = dict()
    for service_key_name, service_resources_base in account_resources_from_deserializer.items():
        if service_key_name == S3_SERVICE_NAME:
            service_key = S3ServiceType()
            value: List[ServiceResourceBase] = [
                from_dict(S3Bucket, service_resource_base_dict) for service_resource_base_dict in service_resources_base
            ]
            account_resources[service_key] = value

    return account_resources


@serde
@dataclass
class AwsAccountResources:
    account_resources: Dict[ServiceType, List[ServiceResourceBase]] = field(
        serializer=to_dict_serializer, deserializer=from_dict_deserializer
    )

    @classmethod
    def load(cls, logger: Logger, aws_account_id: str, session: Session, service_types_to_load: Set[ServiceType]):
        logger.info(f"Start pulling AWS account {aws_account_id} with resources {service_types_to_load}...")
        account_resources: Dict[ServiceType, List[ServiceResourceBase]] = dict()
        for service_type_to_load in service_types_to_load:
            logger.info(f"Start pulling AWS account resources from type {service_type_to_load.get_service_name()}")
            ret: List[ServiceResourceBase] = service_type_to_load.load_service_resources_from_session(logger, session)
            account_resources[service_type_to_load] = ret

        return cls(account_resources=account_resources)