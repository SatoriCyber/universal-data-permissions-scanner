from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TypedDict


import requests


class OauthProviderBase(ABC):  # pylint: disable=too-few-public-methods
    @abstractmethod
    def get_token(self, client_id: str, client_secret: str) -> str:
        pass


class AzureBody(TypedDict):
    grant_type: str
    client_id: str
    client_secret: str
    scope: str


class AzureHeaders(TypedDict):
    content_type: str


@dataclass
class OauthProviderAzure(OauthProviderBase):
    tenant_id: str

    def _get_url(self):
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

    @staticmethod
    def _build_body(client_id: str, client_secret: str) -> AzureBody:
        return AzureBody(
            grant_type="client_credentials",
            client_id=client_id,
            client_secret=client_secret,
            scope="2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default",
        )

    @staticmethod
    def _get_headers() -> AzureHeaders:
        return AzureHeaders(content_type="application/x-www-form-urlencoded")

    @staticmethod
    def _get_timeout() -> int:
        return 60

    def get_token(self, client_id: str, client_secret: str) -> str:
        response = requests.post(
            self._get_url(),
            data=OauthProviderAzure._build_body(client_id, client_secret),
            headers=OauthProviderAzure._get_headers(),  # type: ignore
            timeout=OauthProviderAzure._get_timeout(),
            verify=True,
        )
        access_token: str = response.json()["access_token"]
        return access_token


@dataclass
class OauthProvider:
    client_id: str
    client_secret: str
    provider: OauthProviderBase


def get_authentication_token(oauth_provider: OauthProvider) -> str:
    return oauth_provider.provider.get_token(oauth_provider.client_id, oauth_provider.client_secret)
