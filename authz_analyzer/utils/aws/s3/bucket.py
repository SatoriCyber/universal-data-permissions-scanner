import json
from boto3 import Session
from typing import Dict, Any, Optional, Type, List, Union
from dataclasses import dataclass
from botocore.exceptions import ClientError
from authz_analyzer.utils.aws.iam.policy import PolicyDocument
from authz_analyzer.utils.aws.s3.bucket_acl import S3BucketACL
from authz_analyzer.utils.aws.iam.public_block_access_config import PublicAccessBlockConfiguration


@dataclass
class S3Bucket:
    name: str
    policy_document: Optional[PolicyDocument]
    acl: S3BucketACL
    public_access_block_config: PublicAccessBlockConfiguration


def get_buckets(session: Session) -> Dict[str, S3Bucket]:
    ret = dict()
    s3_client = session.client('s3')
    response = s3_client.list_buckets()
    buckets = response['Buckets']
    for bucket in buckets:
        bucket_name = bucket['Name']
        policy_document = None
        try:
            policy_document = PolicyDocument(
                **json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)['Policy'])
            )
        except ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchBucketPolicy':
                pass
            else:
                raise error

        acl = S3BucketACL(**s3_client.get_bucket_acl(Bucket=bucket_name))
        public_access_block = PublicAccessBlockConfiguration(
            **s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
        )

        ret[bucket_name] = S3Bucket(bucket_name, policy_document, acl, public_access_block)

    return ret
