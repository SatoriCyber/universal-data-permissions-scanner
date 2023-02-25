from dataclasses import dataclass
from logging import Logger
from typing import Any, Dict, Generator, List, Optional, Set, Type

from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.iam.policy.policy_document import Effect, PolicyDocument
from aws_ptrp.principals import Principal, is_stmt_principal_relevant_to_resource
from aws_ptrp.ptrp_models import AwsPrincipalType
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
    aws_account_id: str
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
                logger, self, iam_entities
            )
            if ret:
                self.account_resources[service_type_to_load] = ret

    def yield_service_resources(
        self, service_resource_type: ServiceResourceType
    ) -> Generator[ServiceResourceBase, None, None]:
        service_resources: Optional[Set[ServiceResourceBase]] = self.account_resources.get(service_resource_type)
        if service_resources:
            for service_resource in service_resources:
                yield service_resource

    def yield_stmt_principals_from_resource_based_policy(
        self, principal_type: AwsPrincipalType
    ) -> Generator[Principal, None, None]:
        for service_resource_type, account_resources_service in self.account_resources.items():
            resource_based_irrelevant_principal_types: Optional[
                Set[AwsPrincipalType]
            ] = service_resource_type.get_resource_based_policy_irrelevant_principal_types()

            for account_resource_service in account_resources_service:
                bucket_policy: Optional[PolicyDocument] = account_resource_service.get_resource_policy()
                if bucket_policy:
                    for principal in bucket_policy.yield_resource_based_stmt_principals(Effect.Allow, principal_type):
                        if is_stmt_principal_relevant_to_resource(
                            principal,
                            account_resource_service.get_resource_account_id(),
                            resource_based_irrelevant_principal_types,
                        ):
                            yield principal

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

        return cls(account_resources=account_resources, aws_account_id=aws_account_id)
