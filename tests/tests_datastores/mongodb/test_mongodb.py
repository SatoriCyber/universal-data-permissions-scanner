from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
from unittest.mock import MagicMock, call

import pytest
from pymongo.database import Database

from universal_data_permissions_scanner import MongoDBAuthzAnalyzer
from universal_data_permissions_scanner.datastores.mongodb.model import Privilege, Resource, Role
from universal_data_permissions_scanner.datastores.mongodb.service import MongoDBService
from universal_data_permissions_scanner.datastores.mongodb.service_model import AssignedRole, UserEntry
from universal_data_permissions_scanner.models.model import (
    Asset,
    AssetType,
    AuthzEntry,
    AuthzNote,
    AuthzPathElement,
    AuthzPathElementType,
    Identity,
    IdentityType,
    PermissionLevel,
)
from tests.mocks.mock_writers import MockWriter


@dataclass
class MongoDBServiceMocked:
    _client: Dict[str, MagicMock]
    _mocked_service: MagicMock
    _database_to_users_mapping: Dict[str, List[UserEntry]] = field(default_factory=dict)
    _database_to_roles_mapping: Dict[str, Dict[str, Role]] = field(default_factory=dict)

    @classmethod
    def new(cls) -> MongoDBServiceMocked:
        mocked_client: Dict[str, MagicMock] = {}
        mocked_service = MagicMock(spec=MongoDBService, name="MongoDBServiceMocked")
        mocked_service.client = mocked_client

        mocked_mongodb = cls(mocked_client, mocked_service)
        mocked_service.get_users = MagicMock(side_effect=mocked_mongodb._side_effect_get_users, name="get_client")
        mocked_service.get_custom_roles = MagicMock(
            side_effect=mocked_mongodb._side_effect_get_roles, name="get_client"
        )
        return mocked_mongodb

    def add_database(
        self, database_name: str, users: List[UserEntry], custom_roles: Dict[str, Role], collections: List[str]
    ):
        database_mock = MagicMock(spec=Database, name=database_name)
        database_mock.list_collection_names = MagicMock(return_value=collections, name="list_collection_names")
        database_mock.name = database_name
        self._client[database_name] = database_mock
        self._database_to_users_mapping[database_name] = users
        self._database_to_roles_mapping[database_name] = custom_roles
        return self

    def _side_effect_get_users(self, database_mock_called: MagicMock):
        return self._database_to_users_mapping[database_mock_called.name]  # type: ignore

    def _side_effect_get_roles(self, database_mock_called: MagicMock):
        return self._database_to_roles_mapping[database_mock_called.name]  # type: ignore

    def get_service(self) -> MongoDBService:
        return self._mocked_service


def generate_authz_entry_admin_by_collection(
    role_name: str, permission_level: PermissionLevel, collection_name: List[str], note_on: str
):
    return call(
        AuthzEntry(
            asset=Asset(name=collection_name, type=AssetType.COLLECTION),
            identity=Identity(name="admin", type=IdentityType.USER, id="admin"),
            permission=permission_level,
            path=[
                AuthzPathElement(
                    id=role_name,
                    name=role_name,
                    type=AuthzPathElementType.ROLE,
                    notes=[
                        AuthzNote.to_generic_note(
                            f"user admin has role {role_name} which grants permission {permission_level} on {note_on}"
                        )
                    ],
                )
            ],
        )
    )


@pytest.mark.parametrize(
    "users,custom_roles,expected_writes",
    [
        (  # Test 1: user admin has role clusterManager
            [
                UserEntry(
                    userId=b"admin.admin", user="admin", db="admin", roles=[AssignedRole(role="clusterManager", db="")]
                )
            ],
            {},
            [],
        ),
        (  # Test 2: Cluster admin role
            [UserEntry(userId=b"admin.admin", user="admin", db="admin", roles=[AssignedRole(role="root", db="")])],
            {},
            [
                generate_authz_entry_admin_by_collection(
                    "root", PermissionLevel.FULL, ["admin", "system.roles"], "all databases"
                ),
                generate_authz_entry_admin_by_collection(
                    "root", PermissionLevel.FULL, ["admin", "system.users"], "all databases"
                ),
                generate_authz_entry_admin_by_collection(
                    "root", PermissionLevel.FULL, ["admin", "system.version"], "all databases"
                ),
            ],
        ),
        (  # Test 3: user admin has role read
            [UserEntry(userId=b"admin.admin", user="admin", db="admin", roles=[AssignedRole(role="read", db="admin")])],
            {},
            [
                generate_authz_entry_admin_by_collection(
                    "read", PermissionLevel.READ, ["admin", "system.roles"], "admin.system.roles"
                ),
                generate_authz_entry_admin_by_collection(
                    "read", PermissionLevel.READ, ["admin", "system.users"], "admin.system.users"
                ),
                generate_authz_entry_admin_by_collection(
                    "read", PermissionLevel.READ, ["admin", "system.version"], "admin.system.version"
                ),
            ],
        ),
        (  # Test 4: user admin has custom role
            [
                UserEntry(
                    userId=b"admin.admin", user="admin", db="admin", roles=[AssignedRole(role="grant_role", db="admin")]
                )
            ],
            {
                "grant_role": Role(
                    name="grant_role",
                    db="admin",
                    privileges=[Privilege(resource=Resource(database="", collection=""), actions=["grantRole"])],
                    inherited_roles=[],
                )
            },
            [
                generate_authz_entry_admin_by_collection(
                    "grant_role", PermissionLevel.FULL, ["admin", "system.roles"], "all databases"
                ),
                generate_authz_entry_admin_by_collection(
                    "grant_role", PermissionLevel.FULL, ["admin", "system.users"], "all databases"
                ),
                generate_authz_entry_admin_by_collection(
                    "grant_role", PermissionLevel.FULL, ["admin", "system.version"], "all databases"
                ),
            ],
        ),
    ],
    ids=["Not relevant role", "Cluster admin role", "read role admin database", "Custom Role Cluster"],
)
def test_admin_db(users: List[UserEntry], custom_roles: Dict[str, Role], expected_writes: List[Dict[str, Any]]):
    service = MongoDBServiceMocked.new()
    service.add_database("admin", users, custom_roles, collections=["system.roles", "system.users", "system.version"])
    mocked_writer = MockWriter.new()
    run(service, mocked_writer.get())
    if len(expected_writes) == 0:
        mocked_writer.assert_write_entry_not_called()
    else:
        mocked_writer.mocked_writer.write_entry.assert_has_calls(expected_writes)  # type: ignore


def run(mocked_service: MongoDBServiceMocked, mocked_writer: MagicMock):
    analyzer = MongoDBAuthzAnalyzer(client=mocked_service.get_service(), writer=mocked_writer, logger=MagicMock())
    analyzer.run()
    return analyzer
