from enum import Enum
from model import AuthzEntry
import csv, json

# Type of format to use to output the result
class OutputFormat(Enum):
    JSON = 1
    CSV  = 2

# Base class for formatting and writing the 
# output to a file hander
class OutputWriter:
    
    def __init__(self, fh):
        self.fh = fh

    def write_header(self):
        pass

    def write_entry(self, entry: AuthzEntry):
        pass

    def close(self):
        self.fh.close()

class JSONWriter(OutputWriter):

    def write_entry(self, entry: AuthzEntry):
        path = list(map(lambda x: {
            "type": x.type,
            "id": x.id,
            "name": x.name,
            "note": x.note
        }, entry.path))
        line = {
            "identity": entry.identity,
            "permission": entry.permission,
            "asset": entry.asset,
            "granted_by": path
        }
        json_line = json.dumps(line)
        json_line += '\n'
        self.fh.write(json_line)

class CSVWriter(OutputWriter):

    def __init__(self, fh):
        super().__init__(fh)
        self.writer = csv.writer(self.fh, dialect="excel", escapechar="\\", strict=True)

    def write_header(self):
        self.writer.writerow(["identity", "permission", "asset", "granted_by"])

    def write_entry(self, entry: AuthzEntry):
        path = "->".join(list(map(lambda x: x.id, entry.path)))
        self.writer.writerow([entry.identity, entry.permission, entry.asset, path])