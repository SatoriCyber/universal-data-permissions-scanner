"""Support for Databricks SCIM API.
currently the databricks python client does not support the SCIM API.
So it is our own implementation.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from databricks_cli.sdk.api_client import ApiClient  # type: ignore

from universal_data_permissions_scanner.datastores.databricks.service.model import (
    DatabricksUserResult,
    GroupResult,
    ServicePrincipals,
)

from universal_data_permissions_scanner.datastores.databricks.service.authentication.authentication import (
    Authentication,
)

from universal_data_permissions_scanner.datastores.databricks.service.authentication.basic import BasicAuthentication
from universal_data_permissions_scanner.datastores.databricks.service.authentication.oauth import (
    OauthProvider,
    get_authentication_token,
)

from universal_data_permissions_scanner.datastores.databricks.service.exceptions import UnknownCloudProvider

AWS_ACCOUNT_URL = "https://accounts.cloud.databricks.com"
AZURE_ACCOUNT_URL = "https://accounts.azuredatabricks.net"
GCP_ACCOUNT_URL = "https://accounts.gcp.databricks.com"


BASE_URI = 'accounts'
SCIM_URI = 'scim/v2'


class CloudProvider(Enum):
    """On which cloud provider the account in, will determinate the hostname for the admin console"""

    AZURE = "AZURE"
    GCP = "GCP"
    AWS = "AWS"

    @classmethod
    def from_host(cls, host: str) -> 'CloudProvider':
        """Determinate the cloud provider based on the host"""
        if host.endswith(".azuredatabricks.net"):
            return cls.AZURE
        if host.endswith(".gcp.databricks.com"):
            return cls.GCP
        if host.endswith(".cloud.databricks.com"):
            return cls.AWS
        raise UnknownCloudProvider(f"Failed to resolve host {host} to a cloud provider")

    def account_url(self) -> str:
        """Return the hostname for the admin console"""
        if self == CloudProvider.AZURE:
            return AZURE_ACCOUNT_URL
        if self == CloudProvider.AWS:
            return AWS_ACCOUNT_URL
        if self == CloudProvider.GCP:
            return GCP_ACCOUNT_URL
        raise UnknownCloudProvider


@dataclass
class ScimService:
    client: ApiClient
    account_id: str

    @classmethod
    def load(cls, authentication: Authentication, account_id: str, host: str, **kwargs: Any) -> 'ScimService':
        base_url = CloudProvider.from_host(host).account_url()
        if isinstance(authentication.authentication, BasicAuthentication):
            client = ApiClient(
                host=base_url,
                user=authentication.authentication.username,
                password=authentication.authentication.password,
                **kwargs,
            )
        elif isinstance(authentication.authentication, OauthProvider):  # type: ignore
            token = get_authentication_token(authentication.authentication)
            client = ApiClient(host=base_url, token=token, **kwargs)
        else:
            raise ValueError("Unknown authentication method")
        return cls(client, account_id)

    def list_users(self) -> DatabricksUserResult:
        """Implementation of /api/2.0/preview/scim/v2/Users.
        https://docs.databricks.com/api-explorer/workspace/users/list

        Returns:
            List[User]: List of users
        """
        return self.client.perform_query('GET', self.build_uri('Users'))  # type: ignore

    def list_groups(self) -> GroupResult:
        """Implementation of /api/2.0/preview/scim/v2/Groups.
        https://docs.databricks.com/api-explorer/workspace/groups/list

        Returns:
            GroupResult: List of groups
        """
        return self.client.perform_query('GET', self.build_uri('Groups'))  # type: ignore

    def list_service_principals(self) -> ServicePrincipals:
        return self.client.perform_query('GET', self.build_uri('ServicePrincipals'))  # type: ignore

    def build_uri(self, path: str):
        return f"/{BASE_URI}/{self.account_id}/{SCIM_URI}/{path}"
