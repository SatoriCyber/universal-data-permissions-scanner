from typing import Dict, Any, Optional, Type, List, Union, Tuple, AnyStr, Set
from dataclasses import dataclass
from abc import ABC, abstractmethod


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
