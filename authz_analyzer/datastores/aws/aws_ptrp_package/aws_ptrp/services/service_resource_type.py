from abc import abstractmethod
from logging import Logger
from typing import Dict, Optional, Set, Type

from aws_ptrp.ptrp_models import AwsPrincipalType
from aws_ptrp.services.resolved_stmt import StmtResourcesToResolveCtx
from aws_ptrp.services.service_action_type import ServiceActionType
from aws_ptrp.services.service_resource_base import ServiceResourceBase
from aws_ptrp.services.service_resources_resolver_base import ServiceResourcesResolverBase
from boto3 import Session
from serde import serde

_SERVICE_RESOURCE_TYPE_BY_NAME: Dict[str, Type['ServiceResourceType']] = dict()


def register_service_resource_type_by_name(service_name: str, service_type: Type['ServiceResourceType']):
    _SERVICE_RESOURCE_TYPE_BY_NAME[service_name] = service_type


def get_service_resource_type_by_name(service_name: str) -> Optional[Type['ServiceResourceType']]:
    return _SERVICE_RESOURCE_TYPE_BY_NAME.get(service_name, None)


_SERVICE_RESOURCE_BY_NAME: Dict[str, Type['ServiceResourceBase']] = dict()


def register_service_resource_by_name(service_name: str, service_action: Type['ServiceResourceBase']):
    _SERVICE_RESOURCE_BY_NAME[service_name] = service_action


def get_service_resource_by_name(service_name: str) -> Optional[Type['ServiceResourceBase']]:
    return _SERVICE_RESOURCE_BY_NAME.get(service_name, None)


@serde
class ServiceResourceType(ServiceActionType):
    @abstractmethod
    def get_resource_service_prefix(self) -> str:
        pass

    @classmethod
    @abstractmethod
    def get_service_resources_resolver_type(cls) -> Type[ServiceResourcesResolverBase]:
        pass

    @abstractmethod
    def get_resource_based_policy_irrelevant_principal_types(self) -> Optional[Set[AwsPrincipalType]]:
        pass

    @classmethod
    def load_resolver_service_resources_from_single_stmt(
        cls,
        logger: Logger,
        stmt_ctx: StmtResourcesToResolveCtx,
        not_resource_annotated: bool,
    ) -> ServiceResourcesResolverBase:
        return cls.get_service_resources_resolver_type().load_from_single_stmt(logger, stmt_ctx, not_resource_annotated)

    @classmethod
    def load_service_resources_from_session(
        cls, _logger: Logger, _session: Session, _aws_account_id: str
    ) -> Optional[Set[ServiceResourceBase]]:
        return None

    @classmethod
    def load_service_resources(
        cls,
        _logger: Logger,
        _aws_account_resources,
        _iam_entities,
    ) -> Optional[Set[ServiceResourceBase]]:
        return None
