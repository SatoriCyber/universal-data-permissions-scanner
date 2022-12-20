from typing import Dict, Any, Optional, Type, List, Union, Tuple, AnyStr, Set
from dataclasses import dataclass
from abc import ABC, abstractmethod


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

    # @abstractmethod
    # def get_valid_actions_for_resource(self, other: 'ResolvedServiceResourceBase', all_actions):
    #     pass
