from typing import Optional

import boto3
from boto3 import Session


def create_session_with_assume_role(
    role_arn: str, external_id: Optional[str], role_session_name: Optional[str] = "AwsPtrpSession"
) -> Session:
    # Create a session with the role you want to assume
    sts_client = boto3.client('sts')
    params = {'RoleArn': role_arn, 'RoleSessionName': role_session_name}
    if external_id:
        params['ExternalId'] = external_id

    assumed_role_object = sts_client.assume_role(**params)

    # Use the assumed role's temporary credentials to create a new session
    session = boto3.Session(
        aws_access_key_id=assumed_role_object['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_role_object['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_role_object['Credentials']['SessionToken'],
    )
    return session
