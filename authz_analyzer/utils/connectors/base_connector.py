"""Define base connector that all datastore connectors must implement."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseConnector(ABC):
    @classmethod
    @abstractmethod
    def connect(cls, host: str, username: str, password: str, **kwargs: Any) -> BaseConnector:
        """Connect to the datastore

        Args:
            host (str): Hostname of the datastore
            username (str): Username of the connection
            password (str): Password for the connection
            **kwargs (Any): More args that will be passed to the connector
        """

    @abstractmethod
    def execute(self, command: str, **kwargs: Any) -> list[tuple[Any]] | list[dict[Any, Any]]:
        """Execute a single command against the datastore

        Args:
            command (str): SQL command
            **kwargs (Any): More args to pass to the connector
        """
