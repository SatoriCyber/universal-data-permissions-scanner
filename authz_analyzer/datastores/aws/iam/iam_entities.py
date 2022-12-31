import json
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from typing import Dict, Optional, List, Iterable

import networkx as nx
from boto3 import Session
from serde import serde, from_dict

from authz_analyzer.datastores.aws.iam.iam_groups import IAMGroup, get_iam_groups
from authz_analyzer.datastores.aws.iam.iam_policies import IAMPolicy, get_iam_policies
from authz_analyzer.datastores.aws.actions.account_actions import AwsAccountActions
from authz_analyzer.datastores.aws.services.role_trust.role_trust_principals import RoleTrustServicePrincipalsResolver
from authz_analyzer.datastores.aws.iam.policy.effect import Effect
from authz_analyzer.datastores.aws.iam.policy.principal import StmtPrincipal
from authz_analyzer.datastores.aws.iam.iam_roles import IAMRole, get_iam_roles
from authz_analyzer.datastores.aws.iam.iam_users import IAMUser, get_iam_users


@serde
@dataclass
class IAMEntities:
    account_id: str
    iam_users: Dict[str, IAMUser]  # key is user arn
    iam_groups: Dict[str, IAMGroup]  # key is group arn
    iam_roles: Dict[str, IAMRole]  # key is role arn
    iam_policies: Dict[str, IAMPolicy]  # key is policy arn

    @classmethod
    def load_from_json_file(cls, _logger: Logger, file_path: Path) -> 'IAMEntities':
        with open(file_path, "r", encoding="utf-8") as file:
            analyzed_ctx_json = json.load(file)
            analyzed_ctx_loaded: 'IAMEntities' = from_dict(IAMEntities, analyzed_ctx_json)
            return analyzed_ctx_loaded

    @classmethod
    def load(cls, logger: Logger, aws_account_id: str, session: Session):
        logger.info(f"Start pulling IAM entities from aws account: {aws_account_id}...")
        # Get the iam users
        iam_users = get_iam_users(session)
        logger.info(f"Got iam_users: {iam_users.values()}")

        # Get the iam groups
        iam_groups = get_iam_groups(session)
        logger.info(f"Got iam_groups: {iam_groups.values()}")

        # Get the iam roles
        iam_roles = get_iam_roles(session)
        logger.info(f"Got iam_roles: {iam_roles.values()}")

        # Get the iam policies
        iam_policies = get_iam_policies(session)
        logger.info(f"Got iam_policies: {iam_policies.values()}")
        return cls(
            account_id=aws_account_id,
            iam_users=iam_users,
            iam_groups=iam_groups,
            iam_roles=iam_roles,
            iam_policies=iam_policies,
        )

    def get_trusted_no_entity_principal(
        self, _logger: Logger, trusted_principal: StmtPrincipal
    ) -> Optional[StmtPrincipal]:
        if trusted_principal.is_no_entity_principal():
            return trusted_principal
        return None

    def get_trusted_roles(self, _logger: Logger, trusted_principal: StmtPrincipal) -> Iterable[IAMRole]:
        if trusted_principal.is_all_principals():
            return self.iam_roles.values()
        elif trusted_principal.is_role_principal():
            trusted_role: Optional[IAMRole] = self.iam_roles.get(trusted_principal.get_arn())
            return [trusted_role] if trusted_role else []
        else:
            return []

    def get_trusted_iam_users(self, _logger: Logger, trusted_principal: StmtPrincipal) -> Iterable[IAMUser]:
        if trusted_principal.is_all_principals():
            return self.iam_users.values()
        elif trusted_principal.is_iam_user_principal():
            ret: List[IAMUser] = []
            for iam_user in self.iam_users.values():
                if trusted_principal.contains(iam_user.arn):
                    ret.append(iam_user)
            return ret
        else:
            return []

    def build_principal_network_graph(self, logger: Logger, account_actions: AwsAccountActions) -> nx.DiGraph:
        logger.info(f"Building the principal network graph for aws account id: {self.account_id}")
        g = nx.DiGraph()
        g.add_node("START_NODE")
        g.add_node("END_NODE")
        # First added the iam roles to the graph
        for iam_role in self.iam_roles.values():
            g.add_node(iam_role)

            # Role has attached policies, edged them
            for attached_policy_arn in iam_role.attached_policies_arn:
                policy = self.iam_policies[attached_policy_arn]
                g.add_node(policy)
                g.add_edge(iam_role, policy)
                # there is no such thing policy points to another policy, so edges the policy to the END_NODE
                g.add_edge(policy, "END_NODE")

            # Check the role's trusted entities
            role_trust_service_principal_resolver: Optional[
                RoleTrustServicePrincipalsResolver
            ] = iam_role.assume_role_policy_document.get_role_trust_resolver(
                logger, iam_role.arn, account_actions, Effect.Allow
            )
            if role_trust_service_principal_resolver is None:
                continue

            trusted_principals: List[StmtPrincipal] = role_trust_service_principal_resolver.get_trusted_principals()
            logger.debug("Got role name %s with resolved trusted principal %s", iam_role.role_name, trusted_principals)
            for trusted_principal in trusted_principals:
                trusted_roles: Iterable[IAMRole] = self.get_trusted_roles(logger, trusted_principal)
                for trusted_role in trusted_roles:
                    if trusted_role.arn != iam_role.arn:
                        g.add_edge(trusted_role, iam_role)

                no_entity_principal: Optional[StmtPrincipal] = self.get_trusted_no_entity_principal(
                    logger, trusted_principal
                )
                if no_entity_principal:
                    g.add_edge("START_NODE", no_entity_principal)
                    g.add_edge(no_entity_principal, iam_role)

                trusted_iam_users: Iterable[IAMUser] = self.get_trusted_iam_users(logger, trusted_principal)
                for trusted_iam_user in trusted_iam_users:
                    g.add_edge(trusted_iam_user, iam_role)

            # Role has embedded policies, connect it to the END_NODE
            if len(iam_role.role_policies) != 0:
                g.add_edge(iam_role, "END_NODE")

        for iam_user in self.iam_users.values():
            g.add_node(iam_user)
            g.add_edge("START_NODE", iam_user)
            # A iam user with embedded user policies might achieve access to resource directly
            if len(iam_user.user_policies) != 0:
                g.add_edge(iam_user, "END_NODE")

            for attached_policy_arn in iam_user.attached_policies_arn:
                # policy attached directly to the iam user, additional flow
                policy = self.iam_policies[attached_policy_arn]
                g.add_node(policy)
                g.add_edge(iam_user, policy)
                # there is no such thing policy points to another policy, so edges the policy to the END_NODE
                g.add_edge(policy, "END_NODE")

            for iam_group in self.iam_groups.values():
                # policy attached directly to the iam user, additional flow
                for attached_policy_arn in iam_group.attached_policies_arn:
                    policy = self.iam_policies[attached_policy_arn]
                    g.add_node(policy)
                    g.add_edge(iam_group, policy)
                    g.add_edge(policy, "END_NODE")

                # if current iam_user in part of this iam_group, edged them (and also it relevant roles)
                if iam_user.user_id in iam_group.group_user_ids:
                    g.add_node(iam_group)
                    g.add_edge(iam_user, iam_group)

                # A iam group with embedded user policies might achieve access to resource directly
                if len(iam_group.group_policies) != 0:
                    g.add_edge(iam_group, "END_NODE")

        logger.info(f"Finish to build the principal network graph for aws account id: {self.account_id}: {g}")
        return g
