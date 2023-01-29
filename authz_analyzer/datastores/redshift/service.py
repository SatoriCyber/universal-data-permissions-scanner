from dataclasses import dataclass
from pathlib import Path
from typing import Any, Tuple

import redshift_connector  # type: ignore


@dataclass
class RedshiftService:
    @staticmethod
    def get_rows(redshift_cursor: redshift_connector.Cursor, command_name: Path) -> Tuple[Any, ...]:
        """Get rows from Redshift."""
        command = (Path(__file__).parent / "commands" / command_name).read_text(encoding="utf-8")

        redshift_cursor.execute(command)  # type: ignore
        return redshift_cursor.fetchall()  # type: ignore
