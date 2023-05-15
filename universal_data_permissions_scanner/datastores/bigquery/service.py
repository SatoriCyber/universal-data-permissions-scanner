from dataclasses import dataclass
from typing import Any, Callable, List, Optional

import googleapiclient.discovery  # pylint: disable=import-error
from google.cloud import bigquery, resourcemanager_v3  # pylint: disable=no-name-in-module
from google.api_core.iam import Policy
from google.cloud.resourcemanager_v3.types import Project  # pylint: disable=no-name-in-module
from google.iam.v1 import iam_policy_pb2  # type: ignore

from universal_data_permissions_scanner.datastores.bigquery.policy_tree import CustomPermission, IamPolicyNode


@dataclass
class BigQueryService:  # pylint: disable=(too-many-instance-attributes)
    """BigQueryService is a wrapper for the BigQuery client."""

    project_id: str
    bq_client: bigquery.Client
    project: Project
    projects_client: resourcemanager_v3.ProjectsClient
    folders_client: resourcemanager_v3.FoldersClient
    org_client: resourcemanager_v3.OrganizationsClient
    iam_client: Any  # I don't know how to import this
    org_iam_client: Any
    project_iam_client: Any

    @classmethod
    def load(cls, project_id: str, **kwargs: Any):
        """Connect to the BigQuery.

        Args:
            project_id (str): GCP Project ID
        """
        projects_client = resourcemanager_v3.ProjectsClient(**kwargs)
        project = BigQueryService._get_project(projects_client, project_id)
        folders_client = resourcemanager_v3.FoldersClient(**kwargs)
        org_client = resourcemanager_v3.OrganizationsClient(**kwargs)
        iam_client = googleapiclient.discovery.build("iam", "v1", **kwargs)  # type: ignore
        org_iam_client = iam_client.organizations()  # type: ignore #pylint: disable=no-member
        project_iam_client = iam_client.projects()  # type: ignore #pylint: disable=no-member

        return cls(
            project_id=project_id,
            project=project,
            bq_client=bigquery.Client(project=project_id, **kwargs),
            projects_client=projects_client,
            folders_client=folders_client,
            org_client=org_client,
            iam_client=iam_client,
            org_iam_client=org_iam_client,
            project_iam_client=project_iam_client,
        )

    @staticmethod
    def _get_project(projects_client: resourcemanager_v3.ProjectsClient, project_id: str):
        request = resourcemanager_v3.GetProjectRequest(name=f"projects/{project_id}")
        return projects_client.get_project(request=request)  # type: ignore

    def _get_project_iam(self):
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{self.project_id}"
        )  # pyright: ignore [reportGeneralTypeIssues]
        return self.projects_client.get_iam_policy(request=request)  # type: ignore

    def _get_folder(self, folder_id: str):
        request = resourcemanager_v3.GetFolderRequest(name=folder_id)
        return self.folders_client.get_folder(request=request)  # type: ignore

    def _get_folder_iam(self, folder_id: str) -> Policy:
        request = iam_policy_pb2.GetIamPolicyRequest(resource=folder_id)  # pyright: ignore [reportGeneralTypeIssues]
        return self.folders_client.get_iam_policy(request=request)  # type: ignore

    def _get_organization(self, org_id: str):
        request = resourcemanager_v3.GetOrganizationRequest(name=org_id)
        return self.org_client.get_organization(request=request)  # type: ignore

    def _get_organization_iam(self, org_id: str) -> Policy:
        request = iam_policy_pb2.GetIamPolicyRequest(resource=org_id)  # pyright: ignore [reportGeneralTypeIssues]
        return self.org_client.get_iam_policy(request=request)  # type: ignore

    def list_datasets(self) -> List[str]:
        """List all datasets in the GCP project

        Returns:
            List[str]: A list of all dataset IDs
        """
        return list(map(lambda dataset: dataset.dataset_id, self.bq_client.list_datasets()))  # type: ignore

    def get_dataset(self, dataset_id: str):
        """Get a dataset

        Args:
            dataset_id (str): Dataset ID

        Returns:
            Dataset: A GCP Dataset object
        """
        return self.bq_client.get_dataset(dataset_id)  # type: ignore

    def list_tables(self, dataset_id: str):
        """List all tables in a dataset

        Args:
            dataset_id (str): Dataset ID

        Returns:
            HTTPIterator: Iterator of Table objects
        """
        return self.bq_client.list_tables(dataset_id)  # type: ignore

    def get_table_policy(self, table_fqn: str):
        """Get the IAM policy for a table

        Args:
            table_fqn (str): The table full name, e.g. project.dataset.table

        Returns:
            Policy: A GCP Policy object
        """
        return self.bq_client.get_iam_policy(table_fqn)  # type: ignore

    def lookup_ref(
        self, ref_id: str, resolve_permission_callback: Callable[[str], Optional[CustomPermission]]
    ) -> Optional[IamPolicyNode]:
        """_summary_

        Args:
            ref_id (str): A reference ID, e.g. PROJECT, FOLDER:123, ORGANIZATION:123
            resolve_permission_callback (Callable[[str], Optional[PermissionLevel]]): Resolve permission from role to a permission level

        Returns:
            IamPolicyNode: A node in the IAM policy tree
        """
        if ref_id == "PROJECT":
            return self.lookup_project(resolve_permission_callback)
        return None

    def get_permissions_by_role(self, role: str) -> List[str]:
        """Provide permissions for a given role

        Args:
            role (str): role name, e.g. roles/bigquery.dataViewer

        Returns:
            List[str]: List of permissions, e.g. bigquery.datasets.get
        """
        if role.startswith("organizations/"):
            request = self.org_iam_client.roles().get(name=role)
        elif role.startswith("projects/"):
            request = self.project_iam_client.roles().get(name=role)
        else:
            request = self.iam_client.roles().get(name=role)
        return request.execute()["includedPermissions"]  # type: ignore

    def lookup_project(self, resolve_permission_callback: Callable[[str], Optional[CustomPermission]]):
        """Read project folder and org info

        Returns:
            IamPolicyNode: A node in the IAM policy tree
        """

        project_iam = self._get_project_iam()
        project_node = IamPolicyNode(self.project.name, self.project.project_id, "project", project_iam, resolve_permission_callback)  # type: ignore
        curr = project_node
        parent: Optional[str] = self.project.parent  # type: ignore

        while parent is not None:
            if parent.startswith("folders/"):  # type: ignore #pylint: disable=(E1101:no-member)
                folder = self._get_folder(parent)
                folder_iam = self._get_folder_iam(parent)
                folder_node = IamPolicyNode(
                    folder.name, folder.display_name, "folder", folder_iam, resolve_permission_callback
                )
                curr.set_parent(folder_node)
                # Move to a parent folder or org
                curr = folder_node
                parent: Optional[str] = folder.parent  # type: ignore
            elif parent.startswith("organizations/"):  # type: ignore #pylint: disable=(E1101:no-member)
                org = self._get_organization(parent)
                org_iam = self._get_organization_iam(parent)
                org_node = IamPolicyNode(org.name, org.display_name, "organization", org_iam, resolve_permission_callback)  # type: ignore
                curr.set_parent(org_node)
                # Org is the top level object
                parent = None

        return project_node
