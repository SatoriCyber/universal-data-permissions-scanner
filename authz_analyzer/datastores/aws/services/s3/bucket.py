import json
from dataclasses import dataclass
from typing import List, Optional

from boto3 import Session
from botocore.exceptions import ClientError
from serde import field, from_dict, serde

from authz_analyzer.datastores.aws.iam.policy import PolicyDocument
from authz_analyzer.datastores.aws.iam.public_block_access_config import PublicAccessBlockConfiguration
from authz_analyzer.datastores.aws.services.s3.bucket_acl import S3BucketACL
from authz_analyzer.datastores.aws.services.service_base import ServiceResourceBase
from authz_analyzer.models.model import AssetType

S3_RESOURCE_SERVICE_PREFIX = "arn:aws:s3:::"


@serde
@dataclass
class S3Bucket(ServiceResourceBase):
    name: str
    acl: S3BucketACL
    public_access_block_config: PublicAccessBlockConfiguration
    policy_document: Optional[PolicyDocument] = field(default=None, skip_if_default=True)

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def get_resource_arn(self) -> str:
        return f"{S3_RESOURCE_SERVICE_PREFIX}{self.get_resource_name()}"

    def get_resource_name(self) -> str:
        return self.name

    def get_asset_type(self) -> AssetType:
        return AssetType.S3_BUCKET


def get_buckets(session: Session) -> List[ServiceResourceBase]:
    s3_client = session.client('s3')
    response = s3_client.list_buckets()
    buckets = response['Buckets']
    ret: List[ServiceResourceBase] = []
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
        public_access_block = from_dict(
            PublicAccessBlockConfiguration,
            s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration'],
        )

        ret.append(
            S3Bucket(
                name=bucket_name,
                policy_document=policy_document,
                acl=acl,
                public_access_block_config=public_access_block,
            )
        )

    return ret
