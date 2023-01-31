from abc import ABC, abstractmethod
from dataclasses import dataclass

from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpActionPermissionLevel
from serde import serde


@serde
@dataclass
class ServiceActionBase(ABC):
    @abstractmethod
    def get_action_name(self) -> str:
        pass

    @abstractmethod
    def get_action_permission_level(self) -> AwsPtrpActionPermissionLevel:
        pass
