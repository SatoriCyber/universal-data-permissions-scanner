class AuthzPath:

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