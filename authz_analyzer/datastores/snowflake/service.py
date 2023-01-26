from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple

from snowflake.connector.cursor import SnowflakeCursor

COMMANDS_DIR = Path(__file__).parent / "commands"


@dataclass
class SnowflakeService:
    cursor: SnowflakeCursor

    @classmethod
    def connect(cls, cursor: SnowflakeCursor):
        return cls(cursor=cursor)

    def get_rows(self, file_name_command: Path, params: Optional[str] = None) -> List[Tuple[Any, ...]]:
        """Get rows from Snowflake.

        Args:
            file_name_command (Path): File name to load from the commands directory.
            params (Optional[Tuple[str, ...]], optional): Parameters to pass to the command. Defaults to None.

        Returns:
            List[Tuple[Any, ...]]: results
        """
        command = (COMMANDS_DIR / file_name_command).read_text(encoding="utf-8")
        if params is not None:
            command += " " + params
        self.cursor.execute(command=command)
        return self.cursor.fetchall()  # type: ignore
