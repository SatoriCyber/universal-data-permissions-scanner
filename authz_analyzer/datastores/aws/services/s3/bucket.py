import json
from boto3 import Session
from typing import Dict, Any, Optional, Type, List, Union
from dataclasses import dataclass
from logging import Logger
from botocore.exceptions import ClientError
from authz_analyzer.datastores.aws.iam.policy import PolicyDocument
from authz_analyzer.datastores.aws.services.service_entity_base import ServiceType, ServiceEntityBase
from authz_analyzer.datastores.aws.iam.policy.resolve_service_entities_base import ResolvedServiceEntitiesBase
from authz_analyzer.datastores.aws.services.s3.bucket_acl import S3BucketACL
from authz_analyzer.datastores.aws.iam.public_block_access_config import PublicAccessBlockConfiguration
from serde import serde, field, from_dict


S3_SERVICE_NAME = "s3"
S3_SERVICE_PREFIX = "arn:aws:s3"


@serde
@dataclass
class S3Bucket(ServiceEntityBase):
    name: str
    acl: S3BucketACL
    public_access_block_config: PublicAccessBlockConfiguration
    policy_document: Optional[PolicyDocument] = field(default=None, skip_if_default=True)

    def __repr__(self):
        return self.name

    def get_entity_arn(self) -> str:
        return f"{S3_SERVICE_PREFIX}:::{self.get_entity_name()}"

    def get_entity_name(self) -> str:
        return self.name


@serde
class S3ServiceType(ServiceType):
    def get_service_prefix(self) -> str:
        return S3_SERVICE_PREFIX

    def get_service_name(self) -> str:
        return S3_SERVICE_NAME

    @classmethod
    def load_resolver_service_entities(
        cls, logger: Logger, stmt_relative_id_regex: str, service_entities: List[ServiceEntityBase]
    ) -> ResolvedServiceEntitiesBase:
        # TODO
        pass

    @classmethod
    def load_service_entities_from_session(cls, logger: Logger, session: Session) -> List[ServiceEntityBase]:
        # Get the buckets to analyzed
        buckets = get_buckets(session)
        logger.info(f"Got buckets to analyzed: {buckets}")
        return buckets


def get_buckets(session: Session) -> List[ServiceEntityBase]:
    s3_client = session.client('s3')
    response = s3_client.list_buckets()
    buckets = response['Buckets']
    ret: List[ServiceEntityBase] = []
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
