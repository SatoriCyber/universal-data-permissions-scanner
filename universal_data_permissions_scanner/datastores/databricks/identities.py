from dataclasses import dataclass
from enum import Enum
from logging import Logger
from typing import Dict, Generator, List, Optional

from universal_data_permissions_scanner.datastores.databricks.exceptions import IdentityNotFoundException
from universal_data_permissions_scanner.datastores.databricks.model import (
    DataBricksIdentityId,
    DataBricksIdentityName,
    DataBricksIdentityType,
    DatabricksParsedIdentity,
    ParsedGroup,
)
from universal_data_permissions_scanner.datastores.databricks.service.model import (
    Group,
    GroupMeta,
    ParsedUser,
    Ref,
    ResourceType,
    ServicePrincipal,
)

# Databricks doesn't allow to use the reserved identities to provide permissions.
RESERVED_IDENTITIES = ["DB - RESERVED - account admins"]


class RefType(Enum):
    USER = "Users"
    GROUP = "Groups"
    SERVICE_PRINCIPAL = "ServicePrincipals"


@dataclass
class ParsedRef:
    value: str
    type: RefType


@dataclass
class Identities:
    """Hold all the identities in a Databricks workspace.

    Raises:
        IdentityNotFoundException: If an identity is not found.
    """

    logger: Logger
    users_by_name: Dict[DataBricksIdentityName, ParsedUser]
    users_by_id: Dict[DataBricksIdentityId, ParsedUser]
    groups_by_name: Dict[DataBricksIdentityName, Group]
    groups_by_id: Dict[DataBricksIdentityId, Group]
    service_principals_by_app_id: Dict[DataBricksIdentityName, ServicePrincipal]
    service_principals_by_id: Dict[DataBricksIdentityId, ServicePrincipal]

    @classmethod
    def build_from_databricks_response(
        cls,
        logger: Logger,
        users: List[ParsedUser],
        groups: List[Group],
        service_principals: List[ServicePrincipal],
    ):
        """Receive the output of databricks list users, list groups, list service principals, and build an Identities object.

        Args:
            logger (Logger): _description_
            users (List[DatabricksUser]): _description_
            groups (List[Group]): _description_
            service_principals (List[ServicePrincipal]): _description_

        Returns:
            _type_: _description_
        """
        users_by_name = {user["userName"]: user for user in users if user["active"] is True}
        users_by_id = {user["id"]: user for user in users if user["active"] is True}

        groups_by_name = {group["displayName"]: group for group in groups}
        groups_by_id = {group["id"]: group for group in groups}

        service_principals_by_app_id = {
            service_principal["applicationId"]: service_principal
            for service_principal in service_principals
            if service_principal["active"] is True
        }
        service_principals_by_id = {
            service_principal["id"]: service_principal
            for service_principal in service_principals
            if service_principal["active"] is True
        }

        instance = cls(
            logger,
            users_by_name,
            users_by_id,
            groups_by_name,
            groups_by_id,
            service_principals_by_app_id,
            service_principals_by_id,
        )
        instance._add_builtin_users()
        instance._add_builtin_groups()
        return instance

    def _add_builtin_users(self):
        system_user = ParsedUser(id="1", userName="System user", active=True)
        self.users_by_name["System user"] = system_user
        self.users_by_id["1"] = system_user

    def _add_builtin_groups(self):
        self._add_account_users()

    def _add_account_users(self):
        resource_type = ResourceType.GROUP
        meta = GroupMeta(resourceType=resource_type)
        members_ref = [Ref(ref=value) for value in self.users_by_id.keys()]
        self.groups_by_name["account users"] = Group(
            displayName="account users", id="1", groups=[], members=members_ref, meta=meta
        )

    def resolve_identities(
        self, identity: DataBricksIdentityName, groups: Optional[List[ParsedGroup]] = None
    ) -> Generator[Optional[DatabricksParsedIdentity], None, None]:
        """Resolve an identity to a list of users with groups.
        Args:
            identity (Identity): the identity of the user or group.

        Yields:
            Generator[Optional[DatabricksParsedIdentity], None, None]:
                A user and the groups, for example user1 belongs to group 2, group 2 belongs to group 3 group 3 is the requested identity.
                None for reserved identities.
            The path will be user1 [group 2] [group 3]
        """
        if identity in RESERVED_IDENTITIES:
            yield None
            return
        # handle the first call.
        if groups is None:
            groups = []

        # Databricks doesn't define if the returned permission is a user or a group, so we first check if the identity is a group.
        # if it is, we return all users in the group, and all users in the sub-groups.
        # If it is a user, we return the user.
        try:
            yield from self._resolve_group(identity, groups)
            return
        except IdentityNotFoundException:
            try:
                yield self._resolve_user(identity)
                return
            except IdentityNotFoundException:
                yield self._resolve_service_principal(identity)
                return

    def _resolve_user(self, identity: DataBricksIdentityName):
        try:
            databricks_user = self.users_by_name[identity]
        except KeyError as exc:
            raise IdentityNotFoundException from exc
        return Identities._parse_user(databricks_user)

    def _resolve_service_principal(self, identity: DataBricksIdentityName):
        try:
            service_principal = self.service_principals_by_app_id[identity]
        except KeyError as exc:
            raise IdentityNotFoundException from exc
        return Identities._parse_service_principal(service_principal)

    def _resolve_group(
        self, identity: DataBricksIdentityName, groups: List[ParsedGroup]
    ) -> Generator[DatabricksParsedIdentity, None, None]:
        try:
            group = self.groups_by_name[identity]
        except KeyError as exc:
            raise IdentityNotFoundException from exc
        groups.insert(0, Identities._parse_group(group))
        for member in group.get("members", ()):
            ref = _get_ref(member)
            if ref.type == RefType.USER:
                yield self._get_user_from_ref(ref, groups)
            if ref.type == RefType.GROUP:
                group = self.groups_by_id[ref.value]
                yield from self._resolve_group(group["displayName"], groups)
            if ref.type == RefType.SERVICE_PRINCIPAL:
                service_principal = self.service_principals_by_id[ref.value]
                yield Identities._parse_service_principal(service_principal, groups)

    def _get_user_from_ref(self, ref: ParsedRef, groups: List[ParsedGroup]) -> DatabricksParsedIdentity:
        databricks_user = self.users_by_id[ref.value]
        return Identities._parse_user(databricks_user, groups)

    @staticmethod
    def _parse_user(user: ParsedUser, groups: Optional[List[ParsedGroup]] = None) -> DatabricksParsedIdentity:
        if groups is None:
            groups = []
        return DatabricksParsedIdentity(user["userName"], user["id"], groups, DataBricksIdentityType.USER)

    @staticmethod
    def _parse_group(group: Group) -> ParsedGroup:
        return ParsedGroup(group["id"], group["displayName"])

    @staticmethod
    def _parse_service_principal(
        service_principal: ServicePrincipal, groups: Optional[List[ParsedGroup]] = None
    ) -> DatabricksParsedIdentity:
        if groups is None:
            groups = []
        return DatabricksParsedIdentity(
            service_principal["displayName"],
            service_principal["applicationId"],
            groups,
            DataBricksIdentityType.SERVICE_PRINCIPAL,
        )


def _get_ref(member_ref: Ref):
    """Databricks has a member as a dict with a $ref key, TypedDict doesn't support keys which starts with $ so it is a workaround.

    Args:
        member (MemberRef): Member

    Returns:
        str: ref value
    """
    try:  # Sometimes it is with $ sometimes without.
        ref = member_ref["ref"]  # type: ignore
    except KeyError:
        ref: str = member_ref["$ref"]  # type: ignore
    try:
        ref_type, ref_value = ref.split("/")
    except ValueError:
        ref_value = ref
        ref_type = "Users"
    return ParsedRef(ref_value, RefType(ref_type))
