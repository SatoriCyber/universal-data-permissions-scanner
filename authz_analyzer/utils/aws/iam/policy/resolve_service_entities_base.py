from typing import Dict, Any, Optional, Type, List, Union, Tuple, AnyStr, Set
from abc import ABC, abstractmethod


class ResolvedServiceEntitiesBase:
    @abstractmethod
    def is_empty(self) -> bool:
        pass

    @abstractmethod
    def subtraction_entities_for_actions(self, other: 'ResolvedServiceEntitiesBase', actions):
        pass

    @abstractmethod
    def merge(self, other: 'ResolvedServiceEntitiesBase'):
        pass

    # @abstractmethod
    # def get_valid_actions_for_resource(self, other: 'ResolvedServiceEntityBase', all_actions):
    #     pass
