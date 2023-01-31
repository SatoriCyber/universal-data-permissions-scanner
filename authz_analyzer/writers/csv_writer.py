"""Writer for CSV."""
import csv
from typing import TextIO

from authz_analyzer.models.model import AuthzEntry
from authz_analyzer.writers.base_writers import BaseWriter


class CSVWriter(BaseWriter):
    """Writer for CSV."""

    def __init__(self, fh: TextIO):
        self.writer = csv.writer(fh, dialect="excel", escapechar="\\", strict=True)
        super().__init__(fh)

    def _write_header(self):
        self.writer.writerow(["identity", "permission", "asset", "granted_by"])

    def write_entry(self, entry: AuthzEntry):
        path = "->".join(list(map(lambda x: str(x), entry.path)))
        self.writer.writerow([str(entry.identity), str(entry.permission), str(entry.asset), path])
