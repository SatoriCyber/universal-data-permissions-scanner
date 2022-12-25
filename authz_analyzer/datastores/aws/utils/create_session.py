import boto3
from boto3 import Session


def create_session_with_assume_role(account_id: str, role_name: str, role_session_name="AssumeRoleSession") -> Session:
    # Create a session with the role you want to assume
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn="arn:aws:iam::{}:role/{}".format(account_id, role_name), RoleSessionName=role_session_name
    )

    # Use the assumed role's temporary credentials to create a new session
    session = boto3.Session(
        aws_access_key_id=assumed_role_object['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_role_object['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_role_object['Credentials']['SessionToken'],
    )
    return session
