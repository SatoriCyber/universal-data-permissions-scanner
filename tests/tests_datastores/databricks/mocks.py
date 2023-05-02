from __future__ import annotations

import copy
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from unittest.mock import MagicMock

from universal_data_permissions_scanner.datastores.databricks.analyzer import DatabricksAuthzAnalyzer
from universal_data_permissions_scanner.datastores.databricks.service.model import (
    CatalogList,
    DatabricksUserResult,
    Group,
    GroupResult,
    ParsedUser,
    Privilege,
    PrivilegeAssignments,
    Schema,
    ServicePrincipal,
    ServicePrincipals,
    Table,
    TableType,
)
from universal_data_permissions_scanner.writers.base_writers import BaseWriter


@dataclass
class Entry:
    name: str
    owner: str
    parent: Optional[Entry]
    metastore_id: str = "12345"
    permissions: List[PrivilegeAssignments] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, Entry):
            return False
        return self.name == __o.name

    @abstractmethod
    def add_permission(self, principal: str, privilege: str):
        pass

    def _add_permission(self, principal: str, privilege: str, inherited_from_type: Optional[str]):
        self.permissions.append(
            PrivilegeAssignments(
                principal=principal,
                privileges=[
                    Privilege(
                        privilege=privilege,
                        inherited_from_name=self.name,
                        inherited_from_type=inherited_from_type,
                    )
                ],
            )
        )


@dataclass
class TestCatalog(Entry):
    def to_catalog(self):
        return CatalogList(name=self.name, owner=self.owner, metastore_id=self.metastore_id)

    def add_permission(self, principal: str, privilege: str):
        self._add_permission(principal, privilege, "CATALOG")

    def __hash__(self) -> int:  # pylint: disable=useless-super-delegation
        return super().__hash__()

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, TestCatalog):
            return False
        return super().__eq__(__o)


@dataclass
class TestSchema(Entry):
    def to_schema(self):
        return Schema(name=self.name, owner=self.owner)

    def add_permission(self, principal: str, privilege: str):
        self._add_permission(principal, privilege, "SCHEMA")

    def get_schema_full_name(self):
        return f"{self.parent.name}.{self.name}"  # type: ignore

    def __hash__(self) -> int:  # pylint: disable=useless-super-delegation
        return super().__hash__()

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, TestSchema):
            return False
        return super().__eq__(__o)


@dataclass
class TestTable(Entry):
    @classmethod
    def new_identity_owner_all(cls, username: str, table_name: str, schema_name: str, catalog_name: str):
        catalog = TestCatalog(catalog_name, username, None)
        schema = TestSchema(schema_name, username, catalog)
        return cls(table_name, username, schema)

    def to_table(self):
        full_name = ".".join(self.get_full_name())
        return Table(name=self.name, table_type=TableType.MANAGED, owner=self.owner, full_name=full_name)

    def get_full_name(self):
        schema: TestSchema = self.parent  # type: ignore
        catalog: TestCatalog = schema.parent  # type: ignore
        return [catalog.name, schema.name, self.name]

    def get_schema(self):
        schema: TestSchema = self.parent  # type: ignore
        return schema

    def get_catalog(self):
        schema: TestSchema = self.parent  # type: ignore
        catalog: TestCatalog = schema.parent  # type: ignore
        return catalog

    def add_permission(self, principal: str, privilege: str):
        self.permissions.append(
            PrivilegeAssignments(
                principal=principal,
                privileges=[
                    Privilege(
                        privilege=privilege,
                    )  # type: ignore
                ],
            )
        )


SchemaTableDict = Dict[TestSchema, List[Table]]
SchemaCatalogDict = Dict[TestSchema, TestCatalog]
TableName = str


@dataclass
class DatabricksMock:
    unity_catalog_service: MagicMock
    scim_service: MagicMock
    users: List[ParsedUser] = field(default_factory=list)
    groups: List[Group] = field(default_factory=list)
    service_principals: List[ServicePrincipal] = field(default_factory=list)
    entities_catalog_to_tables: Dict[TestCatalog, SchemaTableDict] = field(default_factory=dict)
    entities_table_to_catalog: Dict[TableName, TestTable] = field(default_factory=dict)
    metastore_id: Optional[str] = None

    @classmethod
    def new(cls, metastore_id: Optional[str] = None):
        scim_service_mock = MagicMock()
        unity_catalog_service_mock = MagicMock()
        instance = cls(unity_catalog_service_mock, scim_service_mock, metastore_id=metastore_id)
        scim_service_mock.list_users = MagicMock(side_effect=instance._side_effect_list_users)
        scim_service_mock.list_groups = MagicMock(side_effect=instance._side_effect_list_groups)
        scim_service_mock.list_service_principals = MagicMock(side_effect=instance._side_effect_list_service_principals)

        unity_catalog_service_mock.list_catalogs = MagicMock(side_effect=instance._side_effect_list_catalogs)
        unity_catalog_service_mock.list_schemas = MagicMock(side_effect=instance._side_effect_list_schemas)
        unity_catalog_service_mock.list_tables = MagicMock(side_effect=instance._side_effect_list_tables)
        unity_catalog_service_mock.get_effective_permissions = MagicMock(
            side_effect=instance._side_effect_get_effective_permissions
        )
        return instance

    def get(self, writer: BaseWriter):
        return DatabricksAuthzAnalyzer(
            writer=writer,
            logger=MagicMock(),
            unity_catalog_service=self.unity_catalog_service,
            scim_service=self.scim_service,
            metastore_id=self.metastore_id,
        )

    def add_table(self, table: TestTable, metastore_id: Optional[str] = None):
        schema: TestSchema = table.parent  # type: ignore
        catalog: TestCatalog = schema.parent  # type: ignore
        if metastore_id is not None:
            catalog.metastore_id = metastore_id
        self.entities_catalog_to_tables.setdefault(catalog, {}).setdefault(schema, []).append(table.to_table())
        table_name = ".".join(table.get_full_name())
        self.entities_table_to_catalog[table_name] = table

    def add_user(self, user: ParsedUser):
        self.users.append(user)

    def add_group(self, group: Group):
        self.groups.append(group)

    def add_service_principal(self, service_principal: ServicePrincipal):
        self.service_principals.append(service_principal)

    def _side_effect_list_users(self):
        return DatabricksUserResult(Resources=self.users)

    def _side_effect_list_groups(self):
        return GroupResult(Resources=self.groups)

    def _side_effect_list_service_principals(self):
        return ServicePrincipals(Resources=self.service_principals)

    def _side_effect_list_catalogs(self):
        return {"catalogs": [test_catalog.to_catalog() for test_catalog in self.entities_catalog_to_tables]}

    def _side_effect_list_schemas(self, catalog_name: str):
        return {"schemas": [schema.to_schema() for schema in self._get_schemas_from_catalog(catalog_name)]}

    def _side_effect_list_tables(self, catalog_name: str, schema_name: str):
        schemas = self._get_schemas_from_catalog(catalog_name)
        return {"tables": self._get_tables_from_schema(schemas, schema_name)}

    def _side_effect_get_effective_permissions(self, _sec_type: str, sec_name: str):
        table = self._get_table_from_table_name(sec_name)
        permissions = copy.copy(table.permissions)
        parent = table.parent

        while parent is not None:
            permissions.extend(parent.permissions)
            parent = parent.parent
        return {
            "privilege_assignments": permissions,
        }

    def _get_table_from_table_name(self, table_name: str):
        try:
            return self.entities_table_to_catalog[table_name]
        except KeyError as err:
            raise ValueError("Table not found") from err

    def _get_schemas_from_catalog(self, catalog_name: str):
        # The owner doesn't matter we just build the key
        catalog = TestCatalog(catalog_name, "owner", None)
        try:
            return self.entities_catalog_to_tables[catalog]
        except KeyError as err:
            raise ValueError("Catalog not found") from err

    @staticmethod
    def _get_tables_from_schema(schema_dict: SchemaTableDict, schema_name: str):
        # The owner doesn't matter we just build the key
        schema = TestSchema(schema_name, "owner", None)
        try:
            return schema_dict[schema]
        except KeyError as err:
            raise ValueError("Schema not found") from err
