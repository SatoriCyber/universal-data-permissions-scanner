from __future__ import annotations

from abc import ABC, abstractmethod


class BaseAuthzAnalyzer(ABC):
    @abstractmethod
    def run(
        self,
    ):
        """Query the datastore for the authorization information, expand it, and
        calls to the writer
        """
        pass
