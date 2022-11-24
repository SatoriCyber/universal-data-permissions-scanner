from enum import Enum
import json

class AuthzEntry:

    def __init__(self, asset):
        self.identity = None
        self.asset = asset
        self.permission = None
        self.path = None
    
    def set_identity(self, identity):
        self.identity = identity

    def set_permission(self, permission):
        self.permission = permission
    
    def set_path(self, path):
        self.path = path

    def __repr__(self):
        return "{} {} {} {}".format(self.identity, self.permission, self.asset, self.path)

class AuthzPathElement:

    def __init__(self, id, name, type, note):
        self.id = id
        self.name = name
        self.type = type
        self.note = note

    def __repr__(self):
        return "{} {} {}".format(self.type, self.id, self.name, self.note)

class OutputFormat(Enum):
    JSON = 1

class Formatter:

    def format(self, entry: AuthzEntry):
        pass

class JSONFormatter(Formatter):

    def format(self, entry: AuthzEntry):
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
        return json.dumps(line)

class AuthzReporter:

    def __init__(self, formatter: Formatter):
        self.formatter = formatter

    def report(authz: AuthzEntry):
        pass

    def close(self):
        pass

class ConsoleReporter(AuthzReporter):

    def __init__(self, formatter: Formatter):
        super().__init__(formatter)

    def report(self, entry: AuthzEntry):
        line = self.formatter.format(entry)
        print(line)

class FileReporter(AuthzReporter):

    def __init__(self, filename, formatter: Formatter):
        super().__init__(formatter)
        self.file = open(filename, 'w')

    def report(self, entry: AuthzEntry):
        line = "{}\n".format(self.formatter.format(entry))
        self.file.write(line)

    def close(self):
        self.file.close()

# Base class for authz analyzers
class AuthzAnalyzer:

    def __init__(self, logger, reporter: AuthzReporter):
        self.logger = logger
        self.reporter = reporter

    def run(self):
        pass