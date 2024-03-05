"""Module for writers building blocks"""

from abc import ABC, abstractmethod
from enum import Enum, auto
from contextlib import contextmanager
from typing import BinaryIO, TextIO, Union, Any, Generator

from universal_data_permissions_scanner.models.model import AuthzEntry

DEFAULT_OUTPUT_FILE = "authz-analyzer-export"


class OutputFormat(Enum):
    """The file format to write the output."""

    CSV = auto()
    MULTI_JSON = auto()


class BaseWriter(ABC):
    """Base class for writers."""

    def __init__(self, fh: Union[TextIO, BinaryIO]) -> None:  # pylint: disable=(invalid-name)
        self.fh = fh  # pylint: disable=(invalid-name)
        self._write_header()

    @abstractmethod
    def _write_header(self) -> None:
        """Writes header of the file.
        Should be called before any write_entry.
        """

    @abstractmethod
    def write_entry(self, entry: AuthzEntry) -> None:
        """Write a single entry to the file.

        Args:
            entry (AuthzEntry): AuthZEntry to write to the file.
        """

    def close(self) -> None:
        """Close the writer."""
        self.fh.close()

    @classmethod
    @contextmanager
    def open(cls, fh: Union[TextIO, BinaryIO]) -> Generator["BaseWriter", Any, None]:  # pylint: disable=(invalid-name)
        """Context manager to open the writer."""
        writer = cls(fh)
        try:
            yield writer
        finally:
            writer.close()
