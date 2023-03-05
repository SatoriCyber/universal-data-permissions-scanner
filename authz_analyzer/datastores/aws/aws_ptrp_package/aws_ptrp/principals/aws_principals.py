from dataclasses import dataclass, field
from logging import Logger
from typing import Dict, List, Optional, Set

from aws_ptrp.iam.iam_entities import IAMAccountEntities, IAMEntities
from aws_ptrp.iam.iam_roles import IAMRole, RoleSession
from aws_ptrp.iam.iam_users import IAMUser
from aws_ptrp.principals.no_entity_principal import NoEntityPrincipal
from aws_ptrp.principals.principal import Principal, PrincipalBase
from aws_ptrp.ptrp_models import AwsPrincipalType
from aws_ptrp.resources.account_resources import AwsAccountResources


@dataclass
class AwsAccountPrincipals:
    iam_user_principals: Dict[str, PrincipalBase] = field(default_factory=dict)
    iam_role_principals: Dict[str, PrincipalBase] = field(default_factory=dict)
    role_session_principals: Dict[str, PrincipalBase] = field(default_factory=dict)
    _all_principals: Optional[Set[PrincipalBase]] = None  # lazy initialization

    def resolve_from_iam_user_principal(self, arn: str, not_principal_annotated: bool) -> Set[PrincipalBase]:
        # return the iam_user and its all federated users
        iam_user: Optional[PrincipalBase] = self.iam_user_principals.get(arn)
        if iam_user is None:
            return set()

        ret: Set[PrincipalBase] = {iam_user}
        assert isinstance(iam_user, IAMUser)

        # When 'NotPrincipal' is used, we need to resolve each federated user individually, if he is in the principal list
        if not not_principal_annotated:
            federated_users = iam_user.get_federated_user_principals()
            if federated_users:
                ret.update(federated_users)
        return ret

    def resolve_from_iam_role_principal(self, arn: str, not_principal_annotated: bool) -> Set[PrincipalBase]:
        # return the iam_role and its all role sessions
        iam_role: Optional[PrincipalBase] = self.iam_role_principals.get(arn)
        if iam_role is None:
            return set()

        ret: Set[PrincipalBase] = {iam_role}
        assert isinstance(iam_role, IAMRole)

        # When 'NotPrincipal' is used, we need to resolve each role session individually, if he is in the principal list
        if not not_principal_annotated:
            role_sessions = iam_role.get_role_sessions()
            if role_sessions:
                ret.update(role_sessions)
        return ret

    def get_role_session_principal(
        self, arn: str, not_principal_annotated: bool, all_stmt_principals: List[Principal]
    ) -> Optional[PrincipalBase]:
        role_session = self.role_session_principals.get(arn)
        if not_principal_annotated and role_session:
            assert isinstance(role_session, RoleSession)
            # We don't want to add the role session if the statement includes 'NotPrincipal' and the iam role which resolves to the
            # role session is not in the statement principals list
            if not any(
                stmt_principal.get_arn() == role_session.iam_role.get_principal().get_arn()
                for stmt_principal in all_stmt_principals
            ):
                return None
        return role_session

    def resolve_federated_user_principals(
        self, federated_user_arn: str, not_principal_annotated: bool, all_stmt_principals: List[Principal]
    ) -> Set[PrincipalBase]:
        # return federated users from every iam_user which resolves the 'federated_user_arn'
        ret: Set[PrincipalBase] = set()
        for iam_user in self.iam_user_principals.values():
            assert isinstance(iam_user, IAMUser)
            for federated_user_principal in iam_user.get_federated_user_principals():
                if federated_user_principal.federated_resource.federated_principal.get_arn() == federated_user_arn:
                    # We don't want to add the federated user if the statement includes 'NotPrincipal' and the iam user which resolves to the
                    # federated user is not in the statement principals list
                    if not_principal_annotated and not any(
                        stmt_principal.get_arn() == iam_user.get_principal().get_arn()
                        for stmt_principal in all_stmt_principals
                    ):
                        break
                    ret.add(federated_user_principal)
                    break
        return ret

    def resolver_account_principals(self) -> Set[PrincipalBase]:
        if self._all_principals is None:
            self._all_principals = set()
            iam_users_and_its_federated_users = set()
            for iam_user_arn in self.iam_user_principals:
                iam_users_and_its_federated_users.update(self.resolve_from_iam_user_principal(iam_user_arn, False))

            self._all_principals.update(
                iam_users_and_its_federated_users,
                self.iam_role_principals.values(),
                self.role_session_principals.values(),
            )
        return self._all_principals


@dataclass
class AwsPrincipals:
    accounts_principals: Dict[str, AwsAccountPrincipals]
    _all_principals: Optional[Set[PrincipalBase]] = None  # lazy initialization

    def _resolve_all_account_principals(self, aws_account_id: str) -> Set[PrincipalBase]:
        ret: Optional[AwsAccountPrincipals] = self.accounts_principals.get(aws_account_id)
        if ret:
            return ret.resolver_account_principals()
        return set()

    def _resolve_all_principals(self) -> Set[PrincipalBase]:
        # For all principals, create principal of no_entity with type ANONYMOUS_USER
        if self._all_principals is None:
            self._all_principals = {NoEntityPrincipal(stmt_principal=Principal.load_anonymous_user())}
            for account_principals in self.accounts_principals.values():
                self._all_principals.update(account_principals.resolver_account_principals())
        return self._all_principals

    def get_all_principals_except_given(self, principals_to_exclude: Set[PrincipalBase]) -> Set[PrincipalBase]:
        return self._resolve_all_principals().difference(principals_to_exclude)

    def get_resolved_principals(
        self,
        stmt_name: Optional[str],
        stmt_parent_arn: str,
        policy_name: Optional[str],
        stmt_principal: Principal,
        all_stmt_principals: List[Principal],
        not_principal_annotated: bool,
    ) -> Optional[Set[PrincipalBase]]:

        if stmt_principal.is_all_principals():
            return self._resolve_all_principals()
        if stmt_principal.is_no_entity_principal():
            return {NoEntityPrincipal(stmt_principal=stmt_principal)}

        # not wildcard/no_entity principal - expect all other types to be with account id
        account_id: Optional[str] = stmt_principal.get_account_id()
        if account_id is None:
            raise Exception(
                f"Failed to resolve principal {stmt_principal} for parent arn {stmt_parent_arn}, policy {policy_name}, stmt {stmt_name} (missing account id)"
            )

        account_principals: Optional[AwsAccountPrincipals] = self.accounts_principals.get(account_id)
        if account_principals:
            if stmt_principal.is_iam_user_principal():
                return account_principals.resolve_from_iam_user_principal(
                    stmt_principal.get_arn(), not_principal_annotated
                )
            elif stmt_principal.is_iam_role_principal():
                return account_principals.resolve_from_iam_role_principal(
                    stmt_principal.get_arn(), not_principal_annotated
                )
            elif stmt_principal.is_federated_user_principal():
                return account_principals.resolve_federated_user_principals(
                    stmt_principal.get_arn(), not_principal_annotated, all_stmt_principals
                )
            elif stmt_principal.is_role_session_principal():
                ret: Optional[PrincipalBase] = account_principals.get_role_session_principal(
                    stmt_principal.get_arn(), not_principal_annotated, all_stmt_principals
                )
                if ret:
                    return {ret}
            elif stmt_principal.is_aws_account():
                return self._resolve_all_account_principals(account_id)
            else:
                raise Exception(
                    f"Failed to resolve principal {stmt_principal} for parent arn {stmt_parent_arn}, policy {policy_name}, stmt {stmt_name} (unknown type)"
                )
        return None

    @staticmethod
    def _update_role_session_from_principal(
        role_session_principal: Principal,
        accounts_principals: Dict[str, AwsAccountPrincipals],
        iam_entities: IAMEntities,
    ):
        # for role session, we can't use the principal arn to lookup the iam_role
        # because, we don't have all the information we need to create the iam_role arn from the arn of the role session
        # needs to go over all the iam_roles and compare the aws account id + role name
        # Example
        # role session arn: arn:aws:sts::982269985744:assumed-role/AWSReservedSSO_AdministratorAccess_3924a5ba0a9f57fd/alon@satoricyber.com
        # role_arn (includes also path) arn:aws:iam::982269985744:role/aws-reserved/sso.amazonaws.com/eu-west-2/AWSReservedSSO_AdministratorAccess_3924a5ba0a9f57fd
        # the role path is missing (/aws-reserved/sso.amazonaws.com/eu-west-2/)
        assert role_session_principal.is_role_session_principal()
        role_session_role_name = role_session_principal.get_role_name()
        role_session_account_id = role_session_principal.get_account_id()
        assert role_session_account_id is not None

        iam_account_entities: Optional[IAMAccountEntities] = iam_entities.iam_accounts_entities.get(
            role_session_account_id
        )
        if iam_account_entities is None:
            return None

        for iam_role_of_session in iam_account_entities.iam_roles.values():
            if (
                iam_role_of_session.role_name == role_session_role_name
                and iam_role_of_session.get_resource_account_id() == role_session_account_id
            ):
                account_principals_to_add_role_session: AwsAccountPrincipals = accounts_principals.setdefault(
                    role_session_account_id, AwsAccountPrincipals()
                )
                role_session = RoleSession(iam_role=iam_role_of_session, role_session_principal=role_session_principal)
                account_principals_to_add_role_session.role_session_principals[
                    role_session_principal.get_arn()
                ] = role_session
                iam_role_of_session.add_role_session(role_session)
        return None

    @classmethod
    def load(
        cls, logger: Logger, iam_entities: IAMEntities, aws_account_resources: AwsAccountResources
    ) -> 'AwsPrincipals':
        logger.info("Loading AWS principals")
        accounts_principals: Dict[str, AwsAccountPrincipals] = {}

        # Handle from iam_entities
        for aws_account_id, iam_entities_for_account in iam_entities.iam_accounts_entities.items():
            account_principals: AwsAccountPrincipals = accounts_principals.setdefault(
                aws_account_id, AwsAccountPrincipals()
            )
            for arn, iam_user in iam_entities_for_account.iam_users.items():
                assert iam_user.get_account_id() == aws_account_id
                account_principals.iam_user_principals[arn] = iam_user

            for arn, iam_role in iam_entities_for_account.iam_roles.items():
                assert iam_role.get_resource_account_id() == aws_account_id
                account_principals.iam_role_principals[arn] = iam_role

        # Handle role session from aws_account_resources

        for role_session_principal in aws_account_resources.yield_stmt_principals_from_resource_based_policy(
            AwsPrincipalType.ASSUMED_ROLE_SESSION
        ):
            AwsPrincipals._update_role_session_from_principal(role_session_principal, accounts_principals, iam_entities)

        return cls(accounts_principals=accounts_principals)
