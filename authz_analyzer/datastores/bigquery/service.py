from google.cloud import bigquery
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2
from authz_analyzer.datastores.bigquery.policy_tree import IamPolicyNode

class BigQueryService():

    def __init__(self, project_id):
        self.project_id = project_id
        self.projects_client = resourcemanager_v3.ProjectsClient()
        self.folders_client = resourcemanager_v3.FoldersClient()
        self.org_client = resourcemanager_v3.OrganizationsClient()
        self.bq_client = bigquery.Client(project=project_id)
        self.project_node = None

    def get_project(self):
        request = resourcemanager_v3.GetProjectRequest(
            name = "projects/%s" % self.project_id,
        )
        return self.projects_client.get_project(request=request)

    def get_project_iam(self):
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource = "projects/%s" % self.project_id,
        )
        return self.projects_client.get_iam_policy(request=request)

    def get_folder(self, folder_id):
        request = resourcemanager_v3.GetFolderRequest(
            name = folder_id
        )
        return self.folders_client.get_folder(request=request)

    def get_folder_iam(self, folder_id):
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource = folder_id
        )
        return self.folders_client.get_iam_policy(request=request)

    def get_organization(self, org_id):
        request = resourcemanager_v3.GetOrganizationRequest(
            name = org_id
        )
        return self.org_client.get_organization(request=request)

    def get_organization_iam(self, org_id):
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource = org_id
        )
        return self.org_client.get_iam_policy(request=request)   

    def list_datasets(self):
        return list(map(lambda dataset: dataset.dataset_id, self.bq_client.list_datasets()))
    
    def get_dataset(self, dataset_id):
        return self.bq_client.get_dataset(dataset_id)

    def list_tables(self, dataset_id):
        return self.bq_client.list_tables(dataset_id)

    def get_table_policy(self, table_fqn):
        return self.bq_client.get_iam_policy(table_fqn)

    def lookup_ref(self, ref_id):
        if ref_id == "PROJECT":
            return self.lookup_project()

    def lookup_project(self):
        if self.project_node is None:
            project = self.get_project()
            project_iam = self.get_project_iam()
            self.project_node = IamPolicyNode(project.name, project.project_id, "project", project_iam)

            # Read project folder and org info
            curr = self.project_node
            parent_id = project.parent
            while parent_id is not None:
                if parent_id.startswith("folders/"):
                    folder = self.get_folder(parent_id)
                    folder_iam = self.get_folder_iam(parent_id)
                    folder_node = IamPolicyNode(folder.name, folder.display_name, "folder", folder_iam)
                    curr.set_parent(folder_node)
                    # Move to a parent folder or org
                    curr = folder_node
                    parent_id = folder.parent
                elif parent_id.startswith("organizations/"):
                    org = self.get_organization(parent_id)
                    org_iam = self.get_organization_iam(parent_id)
                    org_node = IamPolicyNode(org.name, org.display_name, "organization", org_iam)
                    curr.set_parent(org_node)
                    # Org is the top level object
                    parent_id = None
        
        return self.project_node