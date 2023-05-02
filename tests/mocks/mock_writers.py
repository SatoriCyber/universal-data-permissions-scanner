from dataclasses import dataclass
from unittest.mock import MagicMock

from universal_data_permissions_scanner.models.model import AuthzEntry


@dataclass
class MockWriter:
    mocked_writer: MagicMock

    @classmethod
    def new(cls):
        mocked_writer = MagicMock(name="MockWriter")
        mocked_writer.write_entry = MagicMock("MockWriteEntry")
        return cls(mocked_writer)

    def assert_write_entry_called_once_with(self, entry: AuthzEntry):
        self.mocked_writer.write_entry.assert_called_once_with(entry)  # type: ignore

    def assert_write_entry_not_called(self):
        self.mocked_writer.write_entry.assert_not_called()  # type: ignore

    def get(self):
        return self.mocked_writer
