from az_bigquery.service import BigQueryService
from az_bigquery.policy_tree import PolicyNode, DatasetPolicyNode, TableIamPolicyNode, READ, WRITE, FULL
from model import AuthzEntry, AuthzPathElement
from writers import OutputWriter

# This analyzer uses data from BigQuery and GCP IAM to list all possible permissions to BigQuery tables/views.
# 
# The canonical structure of a the authorization graph is as follows:
# Table - may have permissions defined directly on it and inherits the permissions from the dataset.
# Dataset - may have permissions defined directly on it and potentially inherits some permissions from the project.
# Project - may have permissions defined directly on it and inherits the permissions from the folder it's contained in.
# Folder -  may have permissions defined directly on it and inherits the permissions from its parent folder(s) or organization
# Organization - may have permissions defined directly on it
#
# Permissions are defined using roles, see the mapping of role to permissions in the policy_tree module.
class BigQueryAuthzAnalyzer:

    def __init__(self, logger, writer: OutputWriter, project_id):
        self.logger = logger
        self.writer = writer
        self.service = BigQueryService(project_id)
    
    def run(self):
        # Read all tables in all datasets and calculate authz paths
        project_node = self.service.lookup_project()
        for dataset_id in self.service.list_datasets():
            dataset = self.service.get_dataset(dataset_id)
            dataset_node = DatasetPolicyNode(dataset, dataset.access_entries)
            dataset_node.set_parent(project_node)
            tables = self.service.list_tables(dataset_id)
            for table in tables:
                fq_table_id = "{}.{}.{}".format(table.project, table.dataset_id, table.table_id)
                table_iam = self.service.get_table_policy(table.reference)
                table_node = TableIamPolicyNode(fq_table_id, table.table_id, table_iam)
                table_node.set_parent(dataset_node)
                self.calc(fq_table_id, table_node, [])

    # Calculates permissions on the policy node and recursively search for more permissions
    # on the nodes it references or its parent node.
    def calc(self, fq_table_id, node: PolicyNode, path, permissions=[READ, WRITE, FULL]):
        self.logger.debug("calc for %s %s %s permissions = %s path = %s}", fq_table_id, node.type, node.name, permissions, list(map(lambda x: x.type, path)))
        # Start by listing all immediate permissions defined on this node
        for permission in permissions:
            for member in node.get_members(permission):
                self.report_permission(fq_table_id, node, member, permission, path)

        # Then go to each reference and get the permissions from it
        for permission in permissions:
            for member in node.get_references(permission):
                ref_node = self.service.lookup_ref(member["principal"])
                if ref_node is None:
                    self.logger.error("Unable to find ref_node for member {}", member)
                    continue
                note = "{} references {} {} with permission {}".format(node.type, ref_node.type.lower(), ref_node.name, permission)
                self.add_to_path(path, node, note)
                self.calc(fq_table_id, ref_node, path, permissions=[permission])
                path.pop()
        
        # Finally, go to the parent and get the inherited permissions
        if node.parent is None:
            return
        self.goto_parent(fq_table_id, node, path, permissions)

    def goto_parent(self, fq_table_id, node, path, permissions):
        note = "{} is included in {} {}".format(node.type, node.parent.type.lower(), node.parent.name)
        self.add_to_path(path, node, note)
        self.calc(fq_table_id, node.parent, path, permissions)
        path.pop()

    def add_to_path(self, path, node, note):
        self.logger.debug("Adding %s %s to path", node.type, node.name)
        path.append(AuthzPathElement(node.id, node.name, node.type, note))

    def report_permission(self, fq_table_id, node, member, permission, path):
        note = "{} has role {}".format(member["principal"], member["role"])
        self.add_to_path(path, node, note)
        authz = AuthzEntry(fq_table_id)
        authz.set_permission(permission)
        authz.set_identity(member["principal"])
        authz.set_path(path)
        self.writer.write_entry(authz)
        path.pop()


