
class PolicyNode:

    def __init__(self, id, name, type):
        self.id = id
        self.name = name
        self.type = type
        self.parent = None
        self.permissions = {
            READ: [],
            WRITE: [],
            FULL: []
        }
        self.references = {
            READ: [],
            WRITE: [],
            FULL: []
        }

    def set_parent(self, parent):
        self.parent = parent
    
    def add_member(self, member, permission, role):
        self.permissions[permission].append({
            "principal": member,
            "role": role
        })

    def get_members(self, permission):
        return self.permissions[permission]

    def add_reference(self, reference, permission, role):
        self.references[permission].append({
            "principal": reference,
            "role": role
        })

    def get_references(self, permission):
        return self.references[permission]

    def __repr__(self):
        return """%s:
    Parent: %s
    Permissions:
        - READ: %s
        - WRITE: %s
        - FULL: %s
    References:
        - READ: %s
        - WRITE: %s
        - FULL: %s
         """ % (self.name, 
         self.parent,
         self.get_members(READ), self.get_members(WRITE), self.get_members(FULL),
         self.get_references(READ), self.get_references(WRITE), self.get_references(FULL))

class IamPolicyNode(PolicyNode):

    def __init__(self, id, name, type, policy):
        super().__init__(id, name, type)
        for binding in policy.bindings:
            if binding.role is not None:
                permission = ROLE_TO_PERMISSION.get(binding.role)
                if permission is not None:
                    for member in binding.members:
                        super().add_member(member, permission, binding.role)

class TableIamPolicyNode(PolicyNode):

    def __init__(self, id, name, policy):
        super().__init__(id, name, "TABLE")
        for binding in policy.bindings:
            role = binding.get("role")
            if role is not None:
                permission = ROLE_TO_PERMISSION.get(role)
                if permission is not None:
                    for member in binding.get("members"):
                        if member.startswith("user:"):
                            super().add_member(member, permission, role)
                        if member.startswith("serviceAccount:"):
                            super().add_member(member, permission, role)
                        else:
                            super().add_reference(member, permission, role)

class DatasetPolicyNode(PolicyNode):
    def __init__(self, dataset, access_entries):
        id = dataset.dataset_id
        name = dataset.friendly_name if dataset.friendly_name is not None else dataset.dataset_id
        super().__init__(id, name, "DATASET")
        for entry in access_entries:
            if entry.entity_type == "user_by_email":
                super().add_member(entry.entity_id, entry.role, entry.role)
            elif entry.entity_type == "specialGroup" and entry.entity_id in ["projectReaders", "projectWriters", "projectOwners"]:
                super().add_reference("PROJECT", entry.role, entry.entity_id)
            else:
                # catch all just so we don't miss stuff
                # TODO - handle groups, domain, all, etc
                super().add_member(entry.entity_id, entry.role, entry.role)

READ = "READER"
WRITE = "WRITER"
FULL = "OWNER"
ROLE_TO_PERMISSION = {
    "roles/viewer":                          READ,                       
    "roles/editor":                          WRITE,                        
    "roles/owner":                           FULL,                         
    "roles/bigquery.admin":                  FULL,                
    "roles/bigquery.dataEditor":             WRITE,          
    "roles/bigquery.dataOwner":              FULL,            
    "roles/bigquery.dataViewer":             READ,           
    "roles/bigquery.filteredDataViewer":     READ,   
    "roles/bigquery.jobUser":                WRITE,             
    "roles/bigquery.user":                   READ,
    "roles/bigquerydatapolicy.maskedReader": READ
}