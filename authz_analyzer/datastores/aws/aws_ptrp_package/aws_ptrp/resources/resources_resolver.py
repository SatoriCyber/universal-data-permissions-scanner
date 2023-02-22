from dataclasses import dataclass
from logging import Logger
from typing import Dict, List, Optional, Set

from aws_ptrp.principals import PrincipalBase
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services import (
    ServiceActionsResolverBase,
    ServiceActionType,
    ServiceResourceBase,
    ServiceResourcesResolverBase,
    ServiceResourceType,
    StmtResourcesToResolveCtx,
)


@dataclass
class ResourcesResolver:
    @staticmethod
    def _get_stmt_resource_regexes_per_service_type(
        _logger: Logger,
        stmt_resource_regexes: List[str],
        service_types_to_resolve: Set[ServiceResourceType],
    ) -> Dict[ServiceResourceType, List[str]]:
        ret: Dict[ServiceResourceType, List[str]] = dict()
        for stmt_resource_regex in stmt_resource_regexes:
            for service_type in service_types_to_resolve:
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

                regexes_list: List[str] = ret.setdefault(service_type, [])
                regexes_list.append(stmt_relative_id_regex)
        return ret

    @classmethod
    def resolve_stmt_resource_regexes(
        cls,
        logger: Logger,
        stmt_name: Optional[str],
        stmt_parent_arn: str,
        policy_name: Optional[str],
        is_condition_stmt_exists: bool,
        stmt_resource: List[str],
        not_resource_annotated: bool,
        account_resources: AwsAccountResources,
        resolved_stmt_principals: Set[PrincipalBase],
        resolved_stmt_services_action_types: Set[ServiceActionType],
        service_action_stmt_resolvers: Dict[ServiceActionType, ServiceActionsResolverBase],
    ) -> Optional[Dict[ServiceResourceType, ServiceResourcesResolverBase]]:
        services_resource_resolver: Dict[ServiceResourceType, ServiceResourcesResolverBase] = dict()
        # need to resolve resources which resolved by the action resolver & in the account resources
        service_types_to_resolve: Set[ServiceResourceType] = set(
            account_resources.account_resources.keys()
        ).intersection(resolved_stmt_services_action_types)

        if isinstance(stmt_resource, list):
            stmt_resource_regexes = stmt_resource
        else:
            raise Exception(f"Unexpected type of stmt_resource, type: {type(stmt_resource)}")

        ret: Dict[ServiceResourceType, List[str]] = ResourcesResolver._get_stmt_resource_regexes_per_service_type(
            logger, stmt_resource_regexes, service_types_to_resolve
        )
        for service_type, service_regexes in ret.items():
            service_resources: Optional[Set[ServiceResourceBase]] = account_resources.account_resources.get(
                service_type
            )
            service_action_stmt_resolver: Optional[ServiceActionsResolverBase] = service_action_stmt_resolvers.get(
                service_type
            )
            if service_resources and service_action_stmt_resolver and not service_action_stmt_resolver.is_empty():
                stmt_ctx = StmtResourcesToResolveCtx(
                    service_resources=service_resources,
                    resolved_stmt_principals=resolved_stmt_principals,
                    resolved_stmt_actions=service_action_stmt_resolver.get_resolved_actions(),
                    stmt_relative_id_resource_regexes=service_regexes,
                    is_condition_exists=is_condition_stmt_exists,
                    stmt_name=stmt_name,
                    stmt_parent_arn=stmt_parent_arn,
                    policy_name=policy_name,
                )
                service_resource_resolver: ServiceResourcesResolverBase = (
                    service_type.load_resolver_service_resources_from_single_stmt(
                        logger, stmt_ctx, not_resource_annotated
                    )
                )
                if not service_resource_resolver.is_empty():
                    services_resource_resolver[service_type] = service_resource_resolver

        return services_resource_resolver if services_resource_resolver else None
