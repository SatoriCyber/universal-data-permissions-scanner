from dataclasses import dataclass
from typing import Any, List, Optional

from google.cloud import bigquery, resourcemanager_v3  # type: ignore
from google.cloud.resourcemanager_v3.types import Project
from google.iam.v1 import iam_policy_pb2  # type: ignore

from authz_analyzer.datastores.bigquery.policy_tree import IamPolicyNode


@dataclass
class BigQueryService:
    project_id: str
    bq_client: bigquery.Client
    project: Project
    projects_client: resourcemanager_v3.ProjectsClient
    folders_client: resourcemanager_v3.FoldersClient
    org_client: resourcemanager_v3.OrganizationsClient

    @classmethod
    def load(cls, project_id: str, **kwargs: Any):
        projects_client = resourcemanager_v3.ProjectsClient(**kwargs)
        project = BigQueryService._get_project(projects_client, project_id)
        folders_client = resourcemanager_v3.FoldersClient(**kwargs)
        org_client = resourcemanager_v3.OrganizationsClient(**kwargs)

        return cls(
            project_id=project_id,
            project=project,
            bq_client=bigquery.Client(project=project_id, **kwargs),
            projects_client=projects_client,
            folders_client=folders_client,
            org_client=org_client,
        )

    @staticmethod
    def _get_project(projects_client: resourcemanager_v3.ProjectsClient, project_id: str):
        request = resourcemanager_v3.GetProjectRequest(name=f"projects/{project_id}")
        return projects_client.get_project(request=request)  # type: ignore

    def _get_project_iam(self):
        request = iam_policy_pb2.GetIamPolicyRequest(resource=f"projects/{self.project_id}")
        return self.projects_client.get_iam_policy(request=request)  # type: ignore

    def _get_folder(self, folder_id: str):
        request = resourcemanager_v3.GetFolderRequest(name=folder_id)
        return self.folders_client.get_folder(request=request)  # type: ignore

    def _get_folder_iam(self, folder_id: str):
        request = iam_policy_pb2.GetIamPolicyRequest(resource=folder_id)
        return self.folders_client.get_iam_policy(request=request)  # type: ignore

    def _get_organization(self, org_id: str):
        request = resourcemanager_v3.GetOrganizationRequest(name=org_id)
        return self.org_client.get_organization(request=request)  # type: ignore

    def _get_organization_iam(self, org_id: str):
        request = iam_policy_pb2.GetIamPolicyRequest(resource=org_id)
        return self.org_client.get_iam_policy(request=request)  # type: ignore

    def list_datasets(self) -> List[str]:
        return list(map(lambda dataset: dataset.dataset_id, self.bq_client.list_datasets()))  # type: ignore

    def get_dataset(self, dataset_id: str):
        return self.bq_client.get_dataset(dataset_id)  # type: ignore

    def list_tables(self, dataset_id: str):
        return self.bq_client.list_tables(dataset_id)  # type: ignore

    def get_table_policy(self, table_fqn: str):
        return self.bq_client.get_iam_policy(table_fqn)  # type: ignore

    def lookup_ref(self, ref_id: str):
        if ref_id == "PROJECT":
            return self.lookup_project()

    def lookup_project(self):
        """Read project folder and org info

        Returns:
            _type_: _description_
        """

        project_iam = self._get_project_iam()
        project_node = IamPolicyNode(self.project.name, self.project.project_id, "project", project_iam)  # type: ignore
        curr = project_node
        parent: Optional[str] = self.project.parent  # type: ignore

        while parent is not None:
            if parent.startswith("folders/"):  # type: ignore #pylint: disable=(E1101:no-member)
                folder = self._get_folder(parent)
                folder_iam = self._get_folder_iam(parent)
                folder_node = IamPolicyNode(folder.name, folder.display_name, "folder", folder_iam)
                curr.set_parent(folder_node)
                # Move to a parent folder or org
                curr = folder_node
                parent: Optional[str] = folder.parent  # type: ignore
            elif parent.startswith("organizations/"):  # type: ignore #pylint: disable=(E1101:no-member)
                org = self._get_organization(parent)
                org_iam = self._get_organization_iam(parent)
                org_node = IamPolicyNode(org.name, org.display_name, "organization", org_iam)  # type: ignore
                curr.set_parent(org_node)
                # Org is the top level object
                parent: Optional[str] = None

        return project_node
