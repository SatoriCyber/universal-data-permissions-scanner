from abc import ABC, abstractmethod

from serde import serde


@serde
class ServiceType(ABC):
    @abstractmethod
    def get_service_name(self) -> str:
        pass

    def __repr__(self):
        return self.get_service_name()

    def __eq__(self, other):
        return self.get_service_name() == other.get_service_name()

    def __hash__(self):
        return hash(self.get_service_name())
