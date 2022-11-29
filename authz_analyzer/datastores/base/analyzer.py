from abc import ABC, abstractmethod
from logging import Logger

from authz_analyzer.datastores.base.connect_params import BaseConnectParams
from authz_analyzer.writers import BaseWriter


class BaseAuthzAnalyzer(ABC):
    @staticmethod
    @abstractmethod
    def run(params: BaseConnectParams, writer: BaseWriter, logger: Logger):
        """Query the datastore for the authorization information, expand it, and 
        write to the writer

        Args:
            params (BaseConnectParams): Basic connection params, host, username, password etc'
            writer (BaseWriter): Writes the expanded authorization
            logger (Logger): logger
        """
        pass