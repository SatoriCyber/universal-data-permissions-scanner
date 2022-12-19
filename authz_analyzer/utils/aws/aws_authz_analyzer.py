from typing import Any, Dict, List, Optional, Set, Tuple, Union
from boto3 import Session
from dataclasses import dataclass
from logging import Logger
from authz_analyzer.utils.aws.iam.iam_entities import IAMEntities
from authz_analyzer.utils.aws.account_resources import AwsAccountResources
from authz_analyzer.utils.aws.service_entity_base import ServiceType
from serde import serde


@serde
@dataclass
class AwsAuthzAnalyzer:
    account_resources: AwsAccountResources
    iam_entities: IAMEntities

    @classmethod
    def load(cls, logger: Logger, aws_account_id: str, session: Session, service_types_to_load: Set[ServiceType]):
        account_resources = AwsAccountResources.load(logger, aws_account_id, session, service_types_to_load)
        iam_entities = IAMEntities.load(logger, aws_account_id, session)
        return cls(account_resources=account_resources, iam_entities=iam_entities)
