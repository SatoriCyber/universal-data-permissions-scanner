import json
from boto3 import Session
from pathlib import Path
import networkx as nx
from logging import Logger
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from authz_analyzer.datastores.aws.services.s3.bucket import get_buckets, S3Bucket
from authz_analyzer.datastores.aws.iam.iam_users import get_iam_users, IAMUser
from authz_analyzer.datastores.aws.iam.iam_groups import get_iam_groups, IAMGroup
from authz_analyzer.datastores.aws.iam.iam_roles import get_iam_roles, IAMRole
from authz_analyzer.datastores.aws.iam.iam_policies import get_iam_policies, IAMPolicy
from serde import serde, from_dict, serialize, deserialize, serde
from dataclasses import dataclass


@serde
@dataclass
class IAMEntities:
    account_id: str
    iam_users: Dict[str, IAMUser]  # key is user id
    iam_groups: Dict[str, IAMGroup]  # key is group id
    iam_roles: Dict[str, IAMRole]  # key is role id
    iam_policies: Dict[str, IAMPolicy]  # key is policy arn

    @classmethod
    def load_from_json_file(cls, logger, file_path: Path):
        with open(file_path, "r") as f:
            analyzed_ctx_json = json.load(f)
            analyzed_ctx_loaded = from_dict(IAMEntities, analyzed_ctx_json)
            return analyzed_ctx_loaded

    @classmethod
    def load(cls, logger, aws_account_id: str, session: Session):
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

    def build_principal_network_graph(self, logger: Logger):
        logger.info(f"Building the principal network graph for aws account id: {self.account_id}")
        g = nx.DiGraph()
        g.add_node("START_NODE")
        g.add_node("END_NODE")
        # TODO LALON what about role to role ?? possible to get loop in the graph ?

        # First added the iam roles to the graph
        for iam_role in self.iam_roles.values():
            g.add_node(iam_role, name=iam_role.arn)

            # Role has attached policies, edged them
            for attached_policy_arn in iam_role.attached_policies_arn:
                policy = self.iam_policies[attached_policy_arn]
                g.add_node(policy)
                g.add_edge(iam_role, policy)
                # there is no such thing policy points to another policy, so edges the policy to the END_NODE
                g.add_edge(policy, "END_NODE")

            # Role has embedded policies, connect it to the END_NODE
            if len(iam_role.role_policies) != 0:
                g.add_edge(iam_role, "END_NODE")

        for iam_user in self.iam_users.values():
            g.add_node(iam_user, name=iam_user.user_name)
            g.add_edge("START_NODE", iam_user)
            # A iam user with embedded user policies might achieve access to resource directly
            if len(iam_user.user_policies) != 0:
                g.add_edge(iam_user, "END_NODE")

            for attached_policy_arn in iam_user.attached_policies_arn:
                # policy attached directly to the iam user, additional flow
                policy = self.iam_policies[attached_policy_arn]
                g.add_node(policy, name=policy.policy.policy_name)
                g.add_edge(iam_user, policy)
                # there is no such thing policy points to another policy, so edges the policy to the END_NODE
                g.add_edge(policy, "END_NODE")

            # handle iam_roles with trusted policy for this iam_user
            for iam_role in self.iam_roles.values():
                if iam_role.assume_role_policy_document.is_contains_principal(iam_user.arn):
                    # one of the statement contains the principal, edged iam_user -> iam_role
                    g.add_node(iam_role)
                    g.add_edge(iam_user, iam_role)

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

        for node in nx.all_simple_paths(g, source="START_NODE", target="END_NODE"):
            logger.info(f"{node}")

        logger.info(f"Finish to build the principal network graph for aws account id: {self.account_id}: {g}")
        return g
