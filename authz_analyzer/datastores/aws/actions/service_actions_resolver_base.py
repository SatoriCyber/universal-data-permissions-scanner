from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ServiceActionsResolverBase(ABC):
    @abstractmethod
    def is_empty(self) -> bool:
        pass

    # @abstractmethod
    # def subtraction_actions(self, other: 'ServiceActionsResolverBase'):
    #     pass

    @abstractmethod
    def merge(self, other: 'ServiceActionsResolverBase'):
        pass
