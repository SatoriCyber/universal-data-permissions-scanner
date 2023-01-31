from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from aws_ptrp.iam.policy.policy_document import PolicyDocument
from serde import serde


@serde
@dataclass
class ServiceResourceBase(ABC):
    @abstractmethod
    def get_resource_arn(self) -> str:
        pass

    @abstractmethod
    def get_resource_name(self) -> str:
        pass

    @abstractmethod
    def get_resource_policy(self) -> Optional[PolicyDocument]:
        pass

    @abstractmethod
    def get_resource_account_id(self) -> str:
        pass
