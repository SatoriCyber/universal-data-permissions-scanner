from dataclasses import dataclass
from logging import Logger
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from boto3 import Session
from serde import serde

from authz_analyzer.datastores.aws.actions.account_actions import AwsAccountActions
from authz_analyzer.datastores.aws.iam.iam_entities import IAMEntities
from authz_analyzer.datastores.aws.resources.account_resources import AwsAccountResources
from authz_analyzer.datastores.aws.services.service_base import ServiceType


@serde
@dataclass
class AwsAuthzAnalyzer:
    account_actions: AwsAccountActions
    account_resources: AwsAccountResources
    iam_entities: IAMEntities

    @classmethod
    def load(cls, logger: Logger, aws_account_id: str, session: Session, service_types_to_load: Set[ServiceType]):
        account_actions = AwsAccountActions.load(logger, aws_account_id, service_types_to_load)
        account_resources = AwsAccountResources.load(logger, aws_account_id, session, service_types_to_load)
        iam_entities = IAMEntities.load(logger, aws_account_id, session)
        return cls(account_actions=account_actions, account_resources=account_resources, iam_entities=iam_entities)
