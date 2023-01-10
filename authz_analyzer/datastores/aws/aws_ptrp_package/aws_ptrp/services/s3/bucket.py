import json
from dataclasses import dataclass
from typing import Optional, Set

from boto3 import Session
from botocore.exceptions import ClientError
from serde import field, from_dict, serde

from aws_ptrp.iam.policy import PolicyDocument
from aws_ptrp.iam.public_block_access_config import PublicAccessBlockConfiguration
from aws_ptrp.services.s3.bucket_acl import S3BucketACL
from aws_ptrp.services import ServiceResourceBase
from aws_ptrp.permissions_resolver.identity_to_resource_line import ResourceNodeBase
from authz_analyzer.models.model import AssetType


S3_RESOURCE_SERVICE_PREFIX = "arn:aws:s3:::"


@serde
@dataclass
class S3Bucket(ResourceNodeBase, ServiceResourceBase):
    name: str
    acl: S3BucketACL
    public_access_block_config: Optional[PublicAccessBlockConfiguration] = field(default=None, skip_if_default=True)
    policy_document: Optional[PolicyDocument] = field(default=None, skip_if_default=True)

    def __repr__(self):
        return f"S3Bucket({self.name})"

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def get_resource_arn(self) -> str:
        return f"{S3_RESOURCE_SERVICE_PREFIX}{self.get_resource_name()}"

    def get_resource_name(self) -> str:
        return self.name

    def get_resource_policy(self) -> Optional[PolicyDocument]:
        return self.policy_document

    def get_asset_type(self) -> AssetType:
        return AssetType.S3_BUCKET


def get_buckets(session: Session) -> Set[ServiceResourceBase]:
    s3_client = session.client('s3')
    response = s3_client.list_buckets()
    buckets = response['Buckets']
    ret: Set[ServiceResourceBase] = set()
    for bucket in buckets:
        bucket_name = bucket['Name']
        policy_document = None
        try:
            policy_document = from_dict(
                PolicyDocument, json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)['Policy'])
            )
        except ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchBucketPolicy':
                pass
            else:
                raise error

        acl = from_dict(S3BucketACL, s3_client.get_bucket_acl(Bucket=bucket_name))
        public_access_block = None
        try:
            public_access_block = from_dict(
                PublicAccessBlockConfiguration,
                s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration'],
            )
        except ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                pass
            else:
                raise error

        ret.add(
            S3Bucket(
                name=bucket_name,
                policy_document=policy_document,
                acl=acl,
                public_access_block_config=public_access_block,
            )
        )

    return ret
