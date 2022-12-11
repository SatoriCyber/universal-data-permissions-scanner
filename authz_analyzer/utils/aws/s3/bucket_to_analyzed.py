from boto3 import Session
from typing import Dict, Any, Optional, Type
from dataclasses import dataclass
from botocore.exceptions import ClientError
from serde import deserialize, from_dict


@deserialize(rename_all = 'pascalcase')
@dataclass
class PublicAccessBlockConfiguration:
    block_public_acls: bool
    ignore_public_acls: bool
    block_public_policy: bool
    restrict_public_buckets: bool


@dataclass
class S3BucketToAnalyzed:
    name: str
    policy: Optional[Dict[str, Any]]
    acl: Dict[str, Any]
    public_access_block_config: PublicAccessBlockConfiguration


def get_buckets(session: Session) -> Dict[str, S3BucketToAnalyzed]:
    ret = dict()
    s3_client = session.client('s3')
    response = s3_client.list_buckets()
    buckets = response['Buckets']
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = response['Policy']
        except ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchBucketPolicy':
                pass
            else:
                raise error
            
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        acl = {'Owner': acl['Owner'], 'Grants': acl['Grants']}
        
        public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
        public_access_block = from_dict(PublicAccessBlockConfiguration, public_access_block['PublicAccessBlockConfiguration'])
        
        ret[bucket_name] = S3BucketToAnalyzed(bucket_name, policy, acl, public_access_block)

            
    return ret    