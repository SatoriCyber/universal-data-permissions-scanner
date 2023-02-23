from dataclasses import dataclass, field
from logging import Logger
from typing import Dict, Optional, Set

from aws_ptrp.iam.iam_entities import IAMAccountEntities, IAMEntities
from aws_ptrp.iam.iam_roles import RoleSession
from aws_ptrp.iam.policy.policy_document import Effect
from aws_ptrp.principals.no_entity_principal import NoEntityPrincipal
from aws_ptrp.principals.principal import Principal, PrincipalBase
from aws_ptrp.ptrp_models import AwsPrincipalType
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services.federated_user.federated_user_resources import FederatedUserPrincipal


@dataclass
class AwsAccountPrincipals:
    iam_user_principals: Dict[str, PrincipalBase] = field(default_factory=dict)
    iam_role_principals: Dict[str, PrincipalBase] = field(default_factory=dict)
    role_session_principals: Dict[str, PrincipalBase] = field(default_factory=dict)
    federated_user_principals: Dict[str, PrincipalBase] = field(default_factory=dict)
    _all_principals: Optional[Set[PrincipalBase]] = None  # lazy initialization

    def get_iam_user_principal(self, arn: str) -> Optional[PrincipalBase]:
        return self.iam_user_principals.get(arn)

    def get_iam_role_principal(self, arn: str) -> Optional[PrincipalBase]:
        return self.iam_role_principals.get(arn)

    def get_role_session_principal(self, arn: str) -> Optional[PrincipalBase]:
        return self.role_session_principals.get(arn)

    def get_federated_user_principal(self, arn: str) -> Optional[PrincipalBase]:
        return self.federated_user_principals.get(arn)

    def get_account_principals(self) -> Set[PrincipalBase]:
        if self._all_principals is None:
            self._all_principals = set()
            self._all_principals.update(
                self.iam_user_principals.values(),
                self.iam_role_principals.values(),
                self.role_session_principals.values(),
                self.federated_user_principals.values(),
            )
        return self._all_principals


@dataclass
class AwsPrincipals:
    accounts_principals: Dict[str, AwsAccountPrincipals]
    _all_principals: Optional[Set[PrincipalBase]] = None  # lazy initialization

    def _get_all_account_principals(self, aws_account_id: str) -> Set[PrincipalBase]:
        ret: Optional[AwsAccountPrincipals] = self.accounts_principals.get(aws_account_id)
        if ret:
            return ret.get_account_principals()
        return set()

    def _get_all_principals(self) -> Set[PrincipalBase]:
        if self._all_principals is None:
            # For all principals, create principal of no_entity with type ANONYMOUS_USER
            self._all_principals = {NoEntityPrincipal(stmt_principal=Principal.load_anonymous_user())}
            for account_principals in self.accounts_principals.values():
                self._all_principals.update(account_principals.get_account_principals())
        return self._all_principals

    def get_resolved_principals(
        self,
        stmt_name: Optional[str],
        stmt_parent_arn: str,
        policy_name: Optional[str],
        stmt_principal: Principal,
    ) -> Optional[Set[PrincipalBase]]:

        if stmt_principal.is_all_principals():
            return self._get_all_principals()
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
                ret: Optional[PrincipalBase] = account_principals.get_iam_user_principal(stmt_principal.get_arn())
            elif stmt_principal.is_iam_role_principal():
                ret = account_principals.get_iam_role_principal(stmt_principal.get_arn())
            elif stmt_principal.is_role_session_principal():
                ret = account_principals.get_role_session_principal(stmt_principal.get_arn())
            elif stmt_principal.is_federated_user_principal():
                ret = account_principals.get_federated_user_principal(stmt_principal.get_arn())
            elif stmt_principal.is_aws_account():
                return self._get_all_account_principals(account_id)
            else:
                raise Exception(
                    f"Failed to resolve principal {stmt_principal} for parent arn {stmt_parent_arn}, policy {policy_name}, stmt {stmt_name} (unknown type)"
                )
            if ret:
                return {ret}
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
                account_principals_to_add_role_session.role_session_principals[
                    role_session_principal.get_arn()
                ] = RoleSession(iam_role=iam_role_of_session, role_session_principal=role_session_principal)
        return None

    @classmethod
    def load(
        cls, logger: Logger, iam_entities: IAMEntities, aws_account_resources: AwsAccountResources
    ) -> 'AwsPrincipals':
        logger.info("Loading AWS principals")
        accounts_principals: Dict[str, AwsAccountPrincipals] = {}

        # Handle from aws_account_resources
        # from the services resources policy, yield federated-user & role-session principals
        for stmt_principal in aws_account_resources.yield_stmt_principals_from_resource_based_policy(
            AwsPrincipalType.AWS_STS_FEDERATED_USER_SESSION
        ):
            stmt_principal_account_id = stmt_principal.get_account_id()
            assert stmt_principal_account_id is not None
            account_principals_to_add_federated_user: AwsAccountPrincipals = accounts_principals.setdefault(
                stmt_principal_account_id, AwsAccountPrincipals()
            )
            account_principals_to_add_federated_user.federated_user_principals[
                stmt_principal.get_arn()
            ] = FederatedUserPrincipal(federated_principal=stmt_principal)

        for role_session_principal in aws_account_resources.yield_stmt_principals_from_resource_based_policy(
            AwsPrincipalType.ASSUMED_ROLE_SESSION
        ):
            AwsPrincipals._update_role_session_from_principal(role_session_principal, accounts_principals, iam_entities)

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

            for iam_role in iam_entities_for_account.iam_roles.values():
                for role_session_principal in iam_role.assume_role_policy_document.yield_resource_based_stmt_principals(
                    effect=Effect.Allow, principal_type=AwsPrincipalType.ASSUMED_ROLE_SESSION
                ):
                    AwsPrincipals._update_role_session_from_principal(
                        role_session_principal, accounts_principals, iam_entities
                    )

        return cls(accounts_principals=accounts_principals)
