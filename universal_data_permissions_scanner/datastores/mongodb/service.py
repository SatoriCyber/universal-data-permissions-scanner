"""Wrapper for MongoDB client.

To make shortcuts for repeated logic, use the client directly for all others.
"""


from dataclasses import dataclass
from typing import Any

from pymongo import MongoClient  # pylint: disable=import-error
from pymongo.database import Database  # pylint: disable=import-error

from universal_data_permissions_scanner.datastores.mongodb.model import Role
from universal_data_permissions_scanner.datastores.mongodb.service_model import RolesInfoEntry, UserInfoResponseEntry


@dataclass
class MongoDBService:
    client: MongoClient[Any]

    def iter_database_connections(self):
        """Iterate over all database connections."""
        for database in self.client.list_databases():
            database_connection: Database[Any] = self.client[database['name']]
            name: str = database["name"]
            yield (name, database_connection)

    @staticmethod
    def get_users(database_connection: Database[Any]):
        """Get all users."""
        results: UserInfoResponseEntry = database_connection.command("usersInfo")  # type: ignore
        return results['users']

    @staticmethod
    def get_custom_roles(database_connection: Database[Any]):
        """Get all custom roles."""
        results: RolesInfoEntry = database_connection.command({"rolesInfo": 1, "showPrivileges": True})  # type: ignore
        parsed_roles = {role["role"]: Role.build_from_response(role) for role in results['roles']}
        return parsed_roles
