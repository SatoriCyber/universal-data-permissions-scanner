from dataclasses import dataclass
from typing import Union

from universal_data_permissions_scanner.datastores.databricks.service.authentication.basic import BasicAuthentication

from universal_data_permissions_scanner.datastores.databricks.service.authentication.oauth import (
    OauthProvider,
    OauthProviderAzure,
)


@dataclass
class Authentication:
    authentication: Union[BasicAuthentication, OauthProvider]

    @classmethod
    def basic(cls, username: str, password: str):
        return cls(authentication=BasicAuthentication(username=username, password=password))

    @classmethod
    def oauth_azure(cls, client_id: str, client_secret: str, tenant_id: str):
        azure = OauthProviderAzure(tenant_id)
        oauth_provider = OauthProvider(client_id=client_id, client_secret=client_secret, provider=azure)
        return cls(authentication=oauth_provider)
