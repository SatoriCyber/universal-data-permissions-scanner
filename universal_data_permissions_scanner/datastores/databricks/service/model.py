from enum import Enum
from typing import List, Optional, TypedDict


class ParsedUser(TypedDict):
    active: bool
    id: str
    userName: str


class DatabricksUserResult(TypedDict):
    Resources: List[ParsedUser]


class Ref(TypedDict):
    ref: str


class ResourceType(Enum):
    GROUP = "Group"


class GroupMeta(TypedDict):
    resourceType: ResourceType


class Group(TypedDict):
    displayName: str
    meta: GroupMeta
    groups: List[Ref]
    id: str
    members: List[Ref]


class GroupResult(TypedDict):
    Resources: List[Group]


class TableType(Enum):
    MANAGED = "MANAGED"
    EXTERNAL = "EXTERNAL"
    VIEW = "VIEW"
    MATERIALIZED_VIEW = "MATERIALIZED_VIEW"
    STREAMING_TABLE = "STREAMING_TABLE"

    def __str__(self) -> str:
        return self.value


class CatalogList(TypedDict):
    """Definition of databricks catalog.
    https://docs.databricks.com/api-explorer/workspace/catalogs/list

        owner: can be a user or a group
        name: name of the catalog
    """

    name: str
    owner: str
    metastore_id: str


class Schema(TypedDict):
    """Definition of databricks schema.
    https://docs.databricks.com/api-explorer/workspace/schemas/list

        owner: can be a user or a group
        name: name of the schema
    """

    name: str
    owner: str


class Table(TypedDict):
    """Definition of databricks table.
    https://docs.databricks.com/api-explorer/workspace/tables/list

        owner: can be a user or a group
        name: name of the table
    """

    full_name: str
    name: str
    table_type: TableType
    owner: str


class Privilege(TypedDict):
    """Definition of databricks privilege.
    https://docs.databricks.com/api-explorer/workspace/grants/geteffective

        principal: can be a user or a group
        permission: can be READ, WRITE, MANAGE
    """

    inherited_from_name: Optional[str]
    inherited_from_type: Optional[str]
    privilege: str


class PrivilegeAssignments(TypedDict):
    """Definition of databricks permission assignment.
    https://docs.databricks.com/api-explorer/workspace/grants/geteffective

        principal: can be a user or a group
        permission: can be READ, WRITE, MANAGE
    """

    principal: str
    privileges: List[Privilege]


class ServicePrincipal(TypedDict):
    displayName: str
    applicationId: str
    id: str
    active: bool


class ServicePrincipals(TypedDict):
    Resources: List[ServicePrincipal]
