from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, AnyStr, Dict, List, Optional, Set, Tuple, Type, Union


@dataclass
class ServiceActionsResolverBase:
    @abstractmethod
    def is_empty(self) -> bool:
        pass

    # @abstractmethod
    # def subtraction_actions(self, other: 'ServiceActionsResolverBase'):
    #     pass

    @abstractmethod
    def merge(self, other: 'ServiceActionsResolverBase'):
        pass
