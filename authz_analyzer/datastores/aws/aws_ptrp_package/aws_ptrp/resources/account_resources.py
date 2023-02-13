from dataclasses import dataclass
from logging import Logger
from typing import Any, Dict, List, Optional, Set, Type

from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.services import (
    ServiceResourceBase,
    ServiceResourceType,
    get_service_resource_by_name,
    get_service_resource_type_by_name,
)
from boto3 import Session
from serde import field, from_dict, serde, to_dict


def to_dict_serializer(account_resources: Dict[ServiceResourceType, List[ServiceResourceBase]]) -> Dict[str, List[Any]]:
    return dict([(k.get_service_name(), to_dict(v)) for (k, v) in account_resources.items()])


def from_dict_deserializer(
    account_resources_from_deserializer: Dict[str, List[Any]]
) -> Dict[ServiceResourceType, List[ServiceResourceBase]]:
    account_resources: Dict[ServiceResourceType, List[ServiceResourceBase]] = dict()
    for service_key_name, service_resources_base in account_resources_from_deserializer.items():
        service_type: Optional[Type[ServiceResourceType]] = get_service_resource_type_by_name(service_key_name)
        service_resource: Optional[Type[ServiceResourceBase]] = get_service_resource_by_name(service_key_name)
        if service_type and service_resource:
            value: List[ServiceResourceBase] = [
                from_dict(service_resource, service_resource_base_dict)
                for service_resource_base_dict in service_resources_base
            ]  # type: ignore
            account_resources[service_type()] = value
    return account_resources


@serde
@dataclass
class AwsAccountResources:
    account_resources: Dict[ServiceResourceType, Set[ServiceResourceBase]] = field(
        serializer=to_dict_serializer, deserializer=from_dict_deserializer
    )

    def update_services_from_iam_entities(
        self,
        logger: Logger,
        iam_entities: IAMEntities,
        service_types_to_load: Set[ServiceResourceType],
    ):
        # handle loading of resources from iam entities
        for service_type_to_load in service_types_to_load:
            logger.info(
                f"Loading AWS account resources (from iam_entities) for type {service_type_to_load.get_service_name()}"
            )
            ret: Optional[Set[ServiceResourceBase]] = service_type_to_load.load_service_resources(
                logger, self.account_resources, iam_entities
            )
            if ret:
                self.account_resources[service_type_to_load] = ret

    @classmethod
    def load_services_from_session(
        cls,
        logger: Logger,
        aws_account_id: str,
        session: Session,
        service_types_to_load: Set[ServiceResourceType],
    ) -> 'AwsAccountResources':
        logger.info(f"Loading AWS account {aws_account_id} with resources {service_types_to_load}...")
        account_resources: Dict[ServiceResourceType, Set[ServiceResourceBase]] = dict()
        # load resources from the boto3 session
        for service_type_to_load in service_types_to_load:
            logger.info(
                f"Loading AWS account resources (from boto3 session) for type {service_type_to_load.get_service_name()}"
            )
            ret_from_session: Optional[
                Set[ServiceResourceBase]
            ] = service_type_to_load.load_service_resources_from_session(logger, session, aws_account_id)
            if ret_from_session:
                account_resources[service_type_to_load] = ret_from_session

        return cls(account_resources=account_resources)
