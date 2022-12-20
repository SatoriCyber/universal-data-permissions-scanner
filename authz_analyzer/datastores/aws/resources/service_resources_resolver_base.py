from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, AnyStr, Dict, List, Optional, Set, Tuple, Type, Union


@dataclass
class ServiceResourcesResolverBase:
    @abstractmethod
    def is_empty(self) -> bool:
        pass

    # @abstractmethod
    # def subtraction_entities_for_actions(self, other: 'ServiceResourcesResolverBase', actions):
    #     pass

    @abstractmethod
    def merge(self, other: 'ServiceResourcesResolverBase'):
        pass
