from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set, Union

from authz_analyzer.datastores.aws.resources.account_resources import AwsAccountResources
from authz_analyzer.datastores.aws.services.service_base import (
    ServiceActionsResolverBase,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
    ServiceType,
)


@dataclass
class ResourcesResolver:
    # def subtraction(self, other: 'ResolvedResources'):
    #     for resolved_resource in self.resolved_resources:

    # def is_empty(self, type: ResourceType) -> bool:
    #     pass

    @staticmethod
    def _get_stmt_resource_regexes_per_service_type(
        _logger: Logger,
        stmt_resource_regexes: List[str],
        allow_types_to_resolve: Set[ServiceType],
    ) -> Dict[ServiceType, List[str]]:
        ret: Dict[ServiceType, List[str]] = dict()
        for stmt_resource_regex in stmt_resource_regexes:
            for service_type in allow_types_to_resolve:
                service_prefix = service_type.get_resource_service_prefix()
                stmt_relative_id_regex = (
                    "*"
                    if stmt_resource_regex == "*"
                    else stmt_resource_regex[len(service_prefix) :]
                    if stmt_resource_regex.startswith(service_prefix)
                    else None
                )
                if stmt_relative_id_regex is None:
                    continue

                regexes_list: Optional[List[str]] = ret.get(service_type, None)
                if regexes_list:
                    regexes_list.append(stmt_relative_id_regex)
                else:
                    ret[service_type] = [stmt_relative_id_regex]

        return ret

    @classmethod
    def resolve_stmt_resource_regexes(
        cls,
        logger: Logger,
        stmt_resource_regexes: Union[str, List[str]],
        account_resources: AwsAccountResources,
        allow_types_to_resolve: Set[ServiceType],
        service_action_resolvers: Dict[ServiceType, ServiceActionsResolverBase],
    ) -> Optional[Dict[ServiceType, ServiceResourcesResolverBase]]:

        services_resource_resolver: Dict[ServiceType, ServiceResourcesResolverBase] = dict()
        if isinstance(stmt_resource_regexes, str):
            stmt_resource_regexes = [stmt_resource_regexes]

        ret: Dict[ServiceType, List[str]] = ResourcesResolver._get_stmt_resource_regexes_per_service_type(
            logger, stmt_resource_regexes, allow_types_to_resolve
        )
        for service_type, service_regexes in ret.items():
            service_resources: Optional[List[ServiceResourceBase]] = account_resources.account_resources.get(
                service_type
            )
            service_action_resolver: Optional[ServiceActionsResolverBase] = service_action_resolvers.get(service_type)
            if service_resources and service_action_resolver and not service_action_resolver.is_empty():
                service_resource_resolver: ServiceResourcesResolverBase = service_type.load_resolver_service_resources(
                    logger, service_regexes, service_resources, service_action_resolver.get_resolved_actions()
                )
                if not service_resource_resolver.is_empty():
                    services_resource_resolver[service_type] = service_resource_resolver

        return services_resource_resolver if services_resource_resolver else None
