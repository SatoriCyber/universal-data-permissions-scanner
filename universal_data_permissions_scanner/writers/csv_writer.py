"""Writer for CSV."""
import csv
from typing import TextIO

from universal_data_permissions_scanner.models.model import AuthzEntry
from universal_data_permissions_scanner.writers.base_writers import BaseWriter


class CSVWriter(BaseWriter):
    """Writer for CSV."""

    def __init__(self, fh: TextIO):
        self.writer = csv.writer(fh, dialect="excel", escapechar="\\", strict=True)
        super().__init__(fh)

    def _write_header(self):
        self.writer.writerow(["identity", "permission", "asset", "granted_by"])

    def write_entry(self, entry: AuthzEntry):
        path = "->".join([str(x) for x in entry.path])
        self.writer.writerow([str(entry.identity), str(entry.permission), str(entry.asset), path])
