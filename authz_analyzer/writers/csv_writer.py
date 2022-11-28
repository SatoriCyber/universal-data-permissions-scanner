import csv
from typing import TextIO

from authz_analyzer.writers import BaseWriter
from authz_analyzer.models.model import AuthzEntry

class CSVWriter(BaseWriter):
    def __init__(self, fh: TextIO):
        super().__init__(fh)
        self.writer = csv.writer(self.fh, dialect="excel", escapechar="\\", strict=True)

    def write_header(self):
        self.writer.writerow(["identity", "permission", "asset", "granted_by"])

    def write_entry(self, entry: AuthzEntry):
        path = "->".join(list(map(lambda x: x.id, entry.path)))
        self.writer.writerow([entry.identity, entry.permission, entry.asset, path])
