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
from universal_data_permissions_scanner.writers import MultiJsonWriter


def test_csv_writer_write_entry():
    """Test the MultiJson writer write entry"""
    mock_fh = MagicMock()
    mock_write = MagicMock("Write")
    mock_fh.write = mock_write

    asset = Asset(name=["table1"], type=AssetType.TABLE)
    identity = Identity(id="user1", name="user1", type=IdentityType.USER)
    authz_entry_path = AuthzPathElement(id="role1", name="role1", type=AuthzPathElementType.ROLE)
    authz_entry = AuthzEntry(asset=asset, path=[authz_entry_path], identity=identity, permission=PermissionLevel.READ)

    writer = MultiJsonWriter(mock_fh)
    writer.write_entry(authz_entry)
    mock_write.assert_called_once()
