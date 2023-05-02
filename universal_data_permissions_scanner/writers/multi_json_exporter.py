"""Exporter for multi-json.

Each line is a valid json.
Good when there is a need to stream the file to BigQuery.
https://cloud.google.com/bigquery/docs/loading-data-cloud-storage-json#loading_semi-structured_json_data
 """

import json
from typing import Dict, List, Union

from serde.se import to_dict  # pylint: disable=import-error #type: ignore

from universal_data_permissions_scanner.models.model import AuthzEntry
from universal_data_permissions_scanner.writers.base_writers import BaseWriter


class MultiJsonWriter(BaseWriter):
    """Writer for multi-json.
    Each entry is a valid json, example:
    {"identity": {"id": "USER_1", "type": "USER", "name": "USER_1"}, "permission": "Read", "asset": {"name": "db.schema.table", "type": "table"}, "granted_by": [{"type": "ROLE", "id": "super-user", "name": "super-user", "db_permissions": ["SELECT"], "note": "USER_1 has a super-user ROLE"}]}
    """

    def write_entry(self, entry: AuthzEntry):
        path: List[Dict[str, Union[str, List[str]]]] = list(
            map(
                lambda x: {
                    "type": str(x.type),
                    "id": x.id,
                    "name": x.name,
                    "db_permissions": x.db_permissions,
                    "notes": [to_dict(note) for note in x.notes],
                },
                entry.path,
            )
        )
        identity = {
            "id": entry.identity.id,
            "type": str(entry.identity.type),
            "name": entry.identity.name,
            "notes": [to_dict(note) for note in entry.identity.notes],
        }
        asset = {
            "name": entry.asset.name,
            "type": str(entry.asset.type),
            "notes": [to_dict(note) for note in entry.asset.notes],
        }

        line = {
            "identity": identity,
            "permission": str(entry.permission),
            "asset": asset,
            "granted_by": path,
        }
        json_line = json.dumps(line, indent=None)
        json_line += '\n'
        self.fh.write(json_line)

    def _write_header(self):
        pass
