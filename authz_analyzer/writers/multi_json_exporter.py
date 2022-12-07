"""Exporter for multi-json.

Each line is a valid json.
Good when there is a need to stream the file to BigQuery.
Ref: https://cloud.google.com/bigquery/docs/loading-data-cloud-storage-json#loading_semi-structured_json_data 
 """

import json
from typing import Dict, List

from authz_analyzer.models.model import AuthzEntry
from authz_analyzer.writers.base_writers import BaseWriter


class MultiJsonWriter(BaseWriter):
    def write_entry(self, entry: AuthzEntry):
        path: List[Dict[str, str]] = list(
            map(lambda x: {"type": x.type, "id": x.id, "name": x.name, "note": x.note}, entry.path)
        )

        line = {
            "identity": entry.identity,
            "permission": str(entry.permission),
            "asset": entry.asset,
            "granted_by": path,
        }
        json_line = json.dumps(line, indent=None)
        json_line += '\n'
        self.fh.write(json_line)

    def write_header(self):
        pass
