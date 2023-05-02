from __future__ import annotations

from enum import Enum
from logging import Logger
from typing import List, NamedTuple, Optional


class RoleGrant(NamedTuple):
    resource_name: str
    schema_name: str
    resource_type: str
    owner: str
    acl: Optional[str]


class DataBaseAclPermission(Enum):
    SELECT = "r"  # pylint: disable=invalid-name
    INSERT = "a"  # pylint: disable=invalid-name
    UPDATE = "w"  # pylint: disable=invalid-name
    DELETE = "d"  # pylint: disable=invalid-name
    TRUNCATE = "D"  # pylint: disable=invalid-name
    REFERENCES = "x"  # pylint: disable=invalid-name

    def __ge__(self, other: DataBaseAclPermission):
        if self.name in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "TRIGGER"):
            return True
        return False

    def __lt__(self, other: DataBaseAclPermission):
        if self.name in ("SELECT", "REFERENCES"):
            return True
        return False


class DataBaseAclEntry(NamedTuple):
    grantee: str
    permissions: List[DataBaseAclPermission]

    def max_permission(self) -> DataBaseAclPermission:
        """Get the highest permission level."""
        if len(self.permissions) == 0:
            raise ValueError("No permissions")
        return max(self.permissions)  # type: ignore


class DataBaseAcl(NamedTuple):
    entries: List[DataBaseAclEntry]

    @classmethod
    def serialize_from_str(cls, logger: Logger, src: str):
        """Serialize the permission list from a string.
        The string format: {<grantee>=<permission_list>/<grantor>, <grantee>=<permission_list>/<grantor>}
        example:
            {postgres=arwdDxt/postgres,data_access_west=r/postgres}
        """
        entries: List[DataBaseAclEntry] = []
        # remove the curly brackets
        src = src[1:-1]
        for entry in src.split(","):
            grantee, suffix = entry.split("=")
            permission_list = suffix.split("/")[0]
            result_permission_list: List[DataBaseAclPermission] = []
            for letter in permission_list:
                try:
                    result_permission_list.append(DataBaseAclPermission(letter))
                except ValueError:
                    logger.debug("Unknown permission letter: %s", letter)
                    continue

            entries.append(DataBaseAclEntry(grantee=grantee, permissions=result_permission_list))
        return cls(entries=entries)
