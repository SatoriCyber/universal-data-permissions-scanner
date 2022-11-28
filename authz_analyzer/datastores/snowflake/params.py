from dataclasses import dataclass, field
from typing import Any, Dict

from authz_analyzer.datastores.base import BaseConnectParams


@dataclass
class SnowflakeConnectionParameters(BaseConnectParams):
    host: str
    account: str
    username: str
    password: str
    warehouse: str
    snowflake_connection_kwargs: Dict[str, Any] = field(default_factory=lambda: {})

