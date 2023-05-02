"""Support for Databricks SCIM API.
currently the databricks python client does not support the SCIM API.
So it is our own implementation.
"""

from dataclasses import dataclass

from databricks_cli.sdk.api_client import ApiClient  # type: ignore

from universal_data_permissions_scanner.datastores.databricks.service.model import (
    DatabricksUserResult,
    GroupResult,
    ServicePrincipals,
)

BASE_URI = '/preview/scim/v2/'


@dataclass
class ScimService:
    client: ApiClient

    def list_users(self) -> DatabricksUserResult:
        """Implementation of /api/2.0/preview/scim/v2/Users.
        https://docs.databricks.com/api-explorer/workspace/users/list

        Returns:
            List[User]: List of users
        """
        return self.client.perform_query('GET', ScimService.build_uri('Users'))  # type: ignore

    def list_groups(self) -> GroupResult:
        """Implementation of /api/2.0/preview/scim/v2/Groups.
        https://docs.databricks.com/api-explorer/workspace/groups/list

        Returns:
            GroupResult: List of groups
        """
        return self.client.perform_query('GET', ScimService.build_uri('Groups'))  # type: ignore

    def list_service_principals(self) -> ServicePrincipals:
        return self.client.perform_query('GET', ScimService.build_uri('ServicePrincipals'))  # type: ignore

    @staticmethod
    def build_uri(path: str):
        return BASE_URI + path
