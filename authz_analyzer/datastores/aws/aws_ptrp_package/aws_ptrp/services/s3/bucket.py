import json
from dataclasses import dataclass
from typing import Optional, Set

from aws_ptrp.iam.policy import PolicyDocument
from aws_ptrp.iam.public_block_access_config import PublicAccessBlockConfiguration
from aws_ptrp.ptrp_allowed_lines.allowed_line_nodes_base import ResourceNodeBase
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpResourceType
from aws_ptrp.services import ServiceResourceBase
from aws_ptrp.services.s3.bucket_acl import S3BucketACL
from boto3 import Session
from botocore.exceptions import ClientError
from serde import field, from_dict, serde

S3_RESOURCE_SERVICE_PREFIX = "arn:aws:s3:::"


@serde
@dataclass
class S3Bucket(ResourceNodeBase, ServiceResourceBase):
    name: str
    aws_account_id: str
    acl: Optional[S3BucketACL] = field(default=None, skip_if_default=True)
    public_access_block_config: Optional[PublicAccessBlockConfiguration] = field(default=None, skip_if_default=True)
    policy_document: Optional[PolicyDocument] = field(default=None, skip_if_default=True)

    def __repr__(self):
        return f"S3Bucket({self.name})"

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    # impl ServiceResourceBase
    def get_resource_account_id(self) -> str:
        return self.aws_account_id

    def get_resource_arn(self) -> str:
        return f"{S3_RESOURCE_SERVICE_PREFIX}{self.get_resource_name()}"

    def get_resource_name(self) -> str:
        return self.name

    def get_resource_policy(self) -> Optional[PolicyDocument]:
        return self.policy_document

    # impl ResourceNodeBase
    def get_ptrp_resource_type(self) -> AwsPtrpResourceType:
        return AwsPtrpResourceType.S3_BUCKET


def get_buckets(session: Session, aws_account_id: str) -> Set[ServiceResourceBase]:
    s3_client = session.client('s3')
    response = s3_client.list_buckets()
    buckets = response['Buckets']
    ret: Set[ServiceResourceBase] = set()
    for bucket in buckets:
        bucket_name = bucket['Name']
        policy_document: Optional[PolicyDocument] = None
        try:
            policy_document = from_dict(
                PolicyDocument, json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)['Policy'])
            )  # type: ignore
        except ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchBucketPolicy':
                pass
            else:
                raise error

        acl: S3BucketACL = from_dict(S3BucketACL, s3_client.get_bucket_acl(Bucket=bucket_name))  # type: ignore
        public_access_block: Optional[PublicAccessBlockConfiguration] = None
        try:
            public_access_block = from_dict(
                PublicAccessBlockConfiguration,
                s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration'],
            )  # type: ignore
        except ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                pass
            else:
                raise error

        ret.add(
            S3Bucket(
                aws_account_id=aws_account_id,
                name=bucket_name,
                policy_document=policy_document,
                acl=acl,
                public_access_block_config=public_access_block,
            )
        )

    return ret
