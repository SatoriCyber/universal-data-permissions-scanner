from dataclasses import dataclass
from logging import Logger
from typing import List, Optional, Set, Type

import networkx as nx
from boto3 import Session
from serde import field, serde

from authz_analyzer.datastores.aws.actions.account_actions import AwsAccountActions
from authz_analyzer.datastores.aws.iam.iam_entities import IAMEntities
from authz_analyzer.datastores.aws.iam.policy.policy_document import PolicyDocument, PolicyDocumentGetterBase
from authz_analyzer.datastores.aws.resources.account_resources import AwsAccountResources
from authz_analyzer.datastores.aws.services.service_base import ServiceType, get_service_type_by_name
from authz_analyzer.writers.base_writers import BaseWriter


def to_serializer(service_types_to_load: Set[ServiceType]) -> List[str]:
    return [s.get_service_name() for s in service_types_to_load]


def from_deserializer(service_types_to_load_from_deserializer: List[str]) -> Set[ServiceType]:
    service_types_to_load: Set[ServiceType] = set()
    for service_key_name in service_types_to_load_from_deserializer:
        service_type: Optional[Type[ServiceType]] = get_service_type_by_name(service_key_name)
        if service_type:
            service_types_to_load.add(service_type())

    return service_types_to_load


@serde
@dataclass
class AwsAuthzAnalyzer:
    aws_account_id: str
    account_actions: AwsAccountActions
    account_resources: AwsAccountResources
    iam_entities: IAMEntities
    service_types_to_load: Set[ServiceType] = field(serializer=to_serializer, deserializer=from_deserializer)

    @classmethod
    def load(cls, logger: Logger, aws_account_id: str, session: Session, service_types_to_load: Set[ServiceType]):
        account_actions = AwsAccountActions.load(logger, aws_account_id, service_types_to_load)
        account_resources = AwsAccountResources.load(logger, aws_account_id, session, service_types_to_load)
        iam_entities = IAMEntities.load(logger, aws_account_id, session)
        return cls(
            account_actions=account_actions,
            account_resources=account_resources,
            iam_entities=iam_entities,
            aws_account_id=aws_account_id,
            service_types_to_load=service_types_to_load,
        )

    def write_permissions(self, logger: Logger, writer: BaseWriter):
        principal_graph: nx.DiGraph = self.iam_entities.build_principal_network_graph(logger)

        # resolve resources & actions for each policy document
        for node in nx.dfs_preorder_nodes(principal_graph):
            if isinstance(node, PolicyDocumentGetterBase):
                for policy_document in node.policy_documents:  # type: PolicyDocument
                    policy_document.resolve(
                        logger, node.parent_arn, self.account_actions, self.account_resources, self.service_types_to_load
                    )
                    logger.debug(f"{node}, {type(node)}")

        # for iam_user_path in nx.all_simple_paths(principal_graph, source="START_NODE", target="END_NODE"):
        #     for node in iam_user_path[1:-1]:
        #         logger.info(f"{node}, type: {type(node)}")
