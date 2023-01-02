"""Exporter for multi-json.

Each line is a valid json.
Good when there is a need to stream the file to BigQuery.
https://cloud.google.com/bigquery/docs/loading-data-cloud-storage-json#loading_semi-structured_json_data
 """

import json
from typing import Dict, List

from authz_analyzer.models.model import AuthzEntry
from authz_analyzer.writers.base_writers import BaseWriter


class MultiJsonWriter(BaseWriter):
    """Writer for multi-json.
    Each entry is a valid json, example:
    {"identity": {"id": "USER_1", "type": "USER", "name": "USER_1"}, "permission": "Read", "asset": {"name": "db.schema.table", "type": "table"}, "granted_by": [{"type": "ROLE", "id": "super-user", "name": "super-user", "note": "USER_1 has a super-user ROLE"}]}
    """

    def write_entry(self, entry: AuthzEntry):
        path: List[Dict[str, str]] = list(
            map(lambda x: {
                "type": str(x.type),
                "id": x.id,
                "name": x.name,
                "note": x.note,
                "db_permissions": x.db_permissions
            }, entry.path)
        )
        identity = {"id": entry.identity.id, "type": str(entry.identity.type), "name": entry.identity.name}
        asset = {"name": entry.asset.name, "type": str(entry.asset.type)}

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
