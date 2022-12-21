from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from typing import Any, AnyStr, Dict, List, Optional, Set, Tuple, Type, Union

from authz_analyzer.datastores.aws.resources.account_resources import AwsAccountResources
from authz_analyzer.datastores.aws.resources.service_resources_resolver_base import ServiceResourcesResolverBase
from authz_analyzer.datastores.aws.services.service_base import ServiceType


@dataclass
class ResourcesResolver:
    # def subtraction(self, other: 'ResolvedResources'):
    #     for resolved_resource in self.resolved_resources:

    # def is_empty(self, type: ResourceType) -> bool:
    #     pass

    @staticmethod
    def _resolve_stmt_resource_regex(
        logger: Logger,
        stmt_resource_regex: str,
        account_resources: AwsAccountResources,
        allow_types_to_resolve: Set[ServiceType],
    ) -> Dict[ServiceType, ServiceResourcesResolverBase]:
        ret: Dict[ServiceType, ServiceResourcesResolverBase] = dict()
        for service_type, service_resources in account_resources.account_resources.items():
            if service_type not in allow_types_to_resolve:
                continue

            service_prefix = service_type.get_resource_service_prefix()
            stmt_relative_id_regex = (
                "*"
                if stmt_resource_regex == "*"
                else stmt_resource_regex[len(service_prefix):]
                if stmt_resource_regex.startswith(service_prefix)
                else None
            )
            if stmt_relative_id_regex is None:
                continue

            resolved_service_resources: ServiceResourcesResolverBase = service_type.load_resolver_service_resources(
                logger, stmt_relative_id_regex, service_resources
            )
            
            if not resolved_service_resources.is_empty():
                ret[service_type] = resolved_service_resources

        return ret

    @classmethod
    def resolve_stmt_resource_regexes(
        cls,
        logger: Logger,
        stmt_resource_regexes: Union[str, List[str]],
        account_resources: AwsAccountResources,
        allow_types_to_resolve: Set[ServiceType],
    ) -> Optional[Dict[ServiceType, ServiceResourcesResolverBase]]:
        resolved_resources: Dict[ServiceType, ServiceResourcesResolverBase] = dict()
        if isinstance(stmt_resource_regexes, str):
            stmt_resource_regexes = [stmt_resource_regexes]

        for stmt_resource_regex in stmt_resource_regexes:
            ret: Dict[ServiceType, ServiceResourcesResolverBase] = ResourcesResolver._resolve_stmt_resource_regex(
                logger, stmt_resource_regex, account_resources, allow_types_to_resolve
            )
            for service_type, resolved_service_resources in ret.items():
                curr_resolved_service_resources: Optional[ServiceResourcesResolverBase] = resolved_resources.get(
                    service_type, None
                )
                if curr_resolved_service_resources is not None:
                    curr_resolved_service_resources.merge(resolved_service_resources)
                else:
                    resolved_resources[service_type] = resolved_service_resources

        return resolved_resources if resolved_resources else None
