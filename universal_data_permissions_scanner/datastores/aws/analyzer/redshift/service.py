from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Tuple

import redshift_connector  # type: ignore


@dataclass
class RedshiftService:
    @staticmethod
    def get_rows(
        redshift_cursor: redshift_connector.Cursor, command_name: Path, params: Optional[str] = None
    ) -> Tuple[Any, ...]:
        """Get rows from Redshift."""
        command = (Path(__file__).parent / "commands" / command_name).read_text(encoding="utf-8")
        if params is not None:
            command += " " + params

        redshift_cursor.execute(command)  # type: ignore
        return redshift_cursor.fetchall()  # type: ignore
