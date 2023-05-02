from unittest import mock
from unittest.mock import MagicMock

from universal_data_permissions_scanner.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)
from universal_data_permissions_scanner.writers import CSVWriter


@mock.patch('csv.writer')
def test_csv_writer_write_header(_mocked_csv: MagicMock):
    """Test the CSV writer write header."""
    mock_fh = MagicMock()

    writer = CSVWriter(mock_fh)
    writer.writer.writerow.assert_called_once()


def test_csv_writer_write_entry():
    """Test the CSV writer write entry"""
    mocked_csv = MagicMock("MockedCSV")
    mocked_write_row = MagicMock("WriteRow")
    mocked_csv.writerow = mocked_write_row
    mock_fh = MagicMock()

    asset = Asset(name=["table1"], type=AssetType.TABLE)
    identity = Identity(id="user1", name="user1", type=IdentityType.USER)
    authz_entry_path = AuthzPathElement(id="role1", name="role1", type=AuthzPathElementType.ROLE)
    authz_entry = AuthzEntry(asset=asset, path=[authz_entry_path], identity=identity, permission=PermissionLevel.READ)

    writer = CSVWriter(mock_fh)
    writer.writer = mocked_csv
    writer.write_entry(authz_entry)
    mocked_write_row.assert_called_once_with(['USER: user1', 'READ', 'TABLE: table1', 'ROLE role1'])
