from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import TextIO

from authz_analyzer.models.model import AuthzEntry


class OutputFormat(Enum):
    Csv = auto()
    MultiJson = auto()


class BaseWriter(ABC):
    def __init__(self, fh: TextIO) -> None:
        self.fh = fh

    @abstractmethod
    def write_header(self):
        pass

    @abstractmethod
    def write_entry(self, entry: AuthzEntry):
        pass

    def close(self):
        self.fh.close()
