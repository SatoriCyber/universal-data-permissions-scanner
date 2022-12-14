import json
from boto3 import Session
from pathlib import Path
import networkx as nx
from logging import Logger
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel
from authz_analyzer.utils.aws.s3.bucket import get_buckets, S3Bucket
from authz_analyzer.utils.aws.iam.iam_users import get_iam_users, IAMUser
from authz_analyzer.utils.aws.iam.iam_groups import get_iam_groups, IAMGroup
from authz_analyzer.utils.aws.iam.iam_roles import get_iam_roles, IAMRole
from authz_analyzer.utils.aws.iam.iam_policies import get_iam_policies, IAMPolicy


class IAMEntities(BaseModel):
    account_id: str
    iam_users: Dict[str, IAMUser]  # key is user id
    iam_groups: Dict[str, IAMGroup]  # key is group id
    iam_roles: Dict[str, IAMRole]  # key is role id
    iam_policies: Dict[str, IAMPolicy]  # key is policy arn

        
    @classmethod
    def load_from_json_file(cls, logger, file_path: Path):
        with open(file_path, "r") as f:
            analyzed_ctx_json = json.load(f)
            analyzed_ctx_loaded = IAMEntities(**analyzed_ctx_json)
            return analyzed_ctx_loaded

        
    @classmethod
    def load(cls, logger, aws_account_id: str, session: Session):
        logger.info(f"Start pulling IAM entities from aws account: {aws_account_id}...")
        # Get the buckets to analyzed
        buckets = get_buckets(session)
        logger.info(f"Got buckets to analyzed: {buckets.keys()}")
        # Get the iam users
        iam_users = get_iam_users(session)
        logger.info(f"Got iam_users: {iam_users.keys()}")

        # Get the iam groups
        iam_groups = get_iam_groups(session)
        logger.info(f"Got iam_groups: {iam_groups.keys()}")

        # Get the iam roles
        iam_roles = get_iam_roles(session)
        logger.info(f"Got iam_roles: {iam_roles.keys()}")

        # Get the iam policies
        iam_policies = get_iam_policies(session)
        logger.info(f"Got iam_policies: {iam_policies.keys()}")
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
        for iam_user in self.iam_users.values():
            g.add_node(iam_user, name=iam_user.user_name)
            g.add_edge("START_NODE", iam_user)
            g.add_edge(iam_user, "END_NODE")
                            
            for attached_policy_arn in iam_user.attached_policies_arn:
                policy = self.iam_policies[attached_policy_arn]
                g.add_node(policy, name=policy.policy.policy_name)
                g.add_edge(iam_user, policy)
                g.add_edge(policy, "END_NODE")
                
            iam_role_edged_with_iam_user = None
            for iam_role in self.iam_roles.values():
                for attached_policy_arn in iam_role.attached_policies_arn:
                    policy = self.iam_policies[attached_policy_arn]
                    g.add_node(policy)
                    g.add_edge(iam_role, policy)
                    g.add_edge(policy, "END_NODE")
                    
                if len(iam_role.role_policies) != 0:
                    g.add_edge(iam_role, "END_NODE")
                
                if iam_role.assume_role_policy_document.is_contains_principal(iam_user.arn):
                    iam_role_edged_with_iam_user = iam_role
                    g.add_node(iam_role)
                    g.add_edge(iam_user, iam_role)
            
            for iam_group in self.iam_groups.values():
                for attached_policy_arn in iam_group.attached_policies_arn:
                    policy = self.iam_policies[attached_policy_arn]
                    g.add_node(policy)
                    g.add_edge(iam_group, policy)
                    g.add_edge(policy, "END_NODE")
                    
                if iam_user.user_id in iam_group.group_user_ids:
                    g.add_node(iam_group)
                    g.add_edge(iam_user, iam_group)
                    
                if len(iam_group.group_policies) != 0:
                    g.add_edge(iam_group, "END_NODE")                 
                    
                if iam_role_edged_with_iam_user is not None:
                    g.add_edge(iam_group, iam_role_edged_with_iam_user)
            
        
        for node in nx.all_simple_paths(g, source="START_NODE", target="END_NODE"):
            logger.info(f"{node}")
            
        logger.info(f"Finish to build the principal network graph for aws account id: {self.account_id}: {g}")
        return g
