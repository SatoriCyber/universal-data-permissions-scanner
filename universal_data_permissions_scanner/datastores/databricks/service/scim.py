"""Support for Databricks SCIM API.
currently the databricks python client does not support the SCIM API.
So it is our own implementation.
"""

from dataclasses import dataclass
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

ACCOUNT_URL = "https://accounts.cloud.databricks.com"
AZURE_ACCOUNT_URL = "https://accounts.azuredatabricks.net"


BASE_URI = 'accounts'
SCIM_URI = 'scim/v2'


@dataclass
class ScimService:
    client: ApiClient
    account_id: str
    base_url: str

    @classmethod
    def load(cls, authentication: Authentication, account_id: str, is_azure: bool, **kwargs: Any) -> 'ScimService':
        base_url = AZURE_ACCOUNT_URL if is_azure else ACCOUNT_URL
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
        return cls(client, account_id, base_url)

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
