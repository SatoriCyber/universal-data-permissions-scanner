from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Set

IdentityId = id


class IdentityType(Enum):
    USER = auto()
    GROUP = auto()
    ROLE = auto()


class Privilege(Enum):
    # values - https://docs.aws.amazon.com/redshift/latest/dg/r_SVV_RELATION_PRIVILEGES.html
    SELECT = auto()
    INSERT = auto()
    UPDATE = auto()
    DELETE = auto()
    REFERENCES = auto()
    DROP = auto()
    # https: // docs.aws.amazon.com / redshift / latest / dg / r_Privileges.html
    TEMPORARY = auto()
    CREATE = auto()
    USAGE = auto()
    # additional values - https://docs.aws.amazon.com/redshift/latest/dg/r_SVV_DEFAULT_PRIVILEGES.html
    RULE = auto()
    TRIGGER = auto()
    EXECUTE = auto()


@dataclass
class ResourcePrivilege:
    """Define a resource, e.g. a table, and the privilege level."""
    name: str
    privilege_type: Privilege

    def __hash__(self) -> int:
        return hash(self.name)


@dataclass
class DBIdentity:
    """Define an identity, e.g. User, Group, role."""
    id_: IdentityId
    name: str
    type_: IdentityType
    is_admin: bool
    relations: Set[DBIdentity]

    @classmethod
    def new(cls, id_: IdentityId, name: str, type_: IdentityType, relations: Set[DBIdentity], is_admin: bool = False):
        """Create a new DBIdentity."""
        return cls(id_=id_, name=name, type_=type_, is_admin=is_admin, relations=relations)

    def add_relation(self, relations: DBIdentity):
        self.relations.add(relations)

    def __hash__(self) -> int:
        return hash(self.id_)


@dataclass
class AuthorizationModel:
    """Define the authorization model.
    Map a role to the roles it has, and the grants it has.
    Map a role to the grants it has.
    """
    identity_to_identities: Dict[DBIdentity, Set[DBIdentity]]
    identity_to_resource_privilege: Dict[IdentityId, Set[ResourcePrivilege]]
