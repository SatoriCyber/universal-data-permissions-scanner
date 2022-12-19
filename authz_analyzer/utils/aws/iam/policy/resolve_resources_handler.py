from typing import Dict, Any, Optional, Type, List, Union, Tuple, AnyStr, Set
from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import Logger
from authz_analyzer.utils.aws.service_entity_base import ServiceType, ServiceEntityBase
from authz_analyzer.utils.aws.iam.policy.resolve_service_entities_base import ResolvedServiceEntitiesBase
from authz_analyzer.utils.aws.account_resources import AwsAccountResources


@dataclass
class ResolvedResourcesHandler:
    resolved_resources: Dict[ServiceType, ResolvedServiceEntitiesBase]

    # def subtraction(self, other: 'ResolvedResources'):
    #     for resolved_resource in self.resolved_resources:

    # def is_empty(self, type: ResourceType) -> bool:
    #     pass

    @staticmethod
    def resolve_stmt_resource_regex(
        logger: Logger,
        stmt_resource_regex: str,
        account_resources: AwsAccountResources,
        allow_types_to_resolve: Set[ServiceType],
    ) -> Dict[ServiceType, ResolvedServiceEntitiesBase]:
        ret: Dict[ServiceType, ResolvedServiceEntitiesBase] = dict()
        for service_type, service_entities in account_resources.account_resources.items():
            if stmt_resource_regex != "*" or service_type not in allow_types_to_resolve:
                continue

            service_prefix = f"{service_type.get_service_prefix()}:"
            stmt_relative_id_regex = (
                "*"
                if stmt_resource_regex == "*"
                else stmt_resource_regex[len(service_prefix) :]
                if stmt_resource_regex.startswith(service_prefix)
                else None
            )
            if stmt_relative_id_regex is None:
                continue

            resolved_service_entities: ResolvedServiceEntitiesBase = service_type.load_resolver_service_entities(
                logger, stmt_relative_id_regex, service_entities
            )
            ret[service_type] = resolved_service_entities

        return ret

    @classmethod
    def load_from_stmt_resource_regexes(
        cls,
        logger: Logger,
        stmt_resource_regexes: Union[str, List[str]],
        account_resources: AwsAccountResources,
        allow_types_to_resolve: Set[ServiceType],
    ) -> 'ResolvedResourcesHandler':
        resolved_resources: Dict[ServiceType, ResolvedServiceEntitiesBase] = dict()
        if isinstance(stmt_resource_regexes, str):
            stmt_resource_regexes = [stmt_resource_regexes]

        for stmt_resource_regex in stmt_resource_regexes:
            ret: Dict[ServiceType, ResolvedServiceEntitiesBase] = ResolvedResourcesHandler.resolve_stmt_resource_regex(
                logger, stmt_resource_regex, account_resources, allow_types_to_resolve
            )
            for service_type, resolved_service_entities in ret.items():
                curr_resolved_service_entities: Optional[ResolvedServiceEntitiesBase] = resolved_resources.get(
                    service_type, None
                )
                if curr_resolved_service_entities is not None:
                    curr_resolved_service_entities.merge(resolved_service_entities)
                else:
                    resolved_resources[service_type] = resolved_service_entities

        return cls(resolved_resources=resolved_resources)
