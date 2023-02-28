from unittest.mock import MagicMock, patch

from aws_ptrp.utils.create_session import create_session_with_assume_role

TARGET_ACCOUNT_ID = 123456123465
ADDITIONAL_ACCOUNT_ID = 654321654321
target_account_session_params = {
    "role_arn": f"arn:aws:iam::{TARGET_ACCOUNT_ID}:role/SatoriScanner",
    "external_id": "0000",
    "role_session_name": "RoleSessionName",
}
additional_account_session_params = {
    "role_arn": f"arn:aws:iam::{TARGET_ACCOUNT_ID}:role/SatoriScanner",
    "external_id": "0000",
    "role_session_name": "RoleSessionName",
}
target_account_assume_role_called_with = {
    'RoleArn': target_account_session_params['role_arn'],
    'RoleSessionName': target_account_session_params['role_session_name'],
    'ExternalId': target_account_session_params['external_id'],
}
additional_account_assume_role_called_with = {
    'RoleArn': additional_account_session_params['role_arn'],
    'RoleSessionName': additional_account_session_params['role_session_name'],
    'ExternalId': additional_account_session_params['external_id'],
}
target_account_assume_role_response = {
    'Credentials': {
        'AccessKeyId': 'TargetAccount_AccessKeyIdValue',
        'SecretAccessKey': 'TargetAccount_SecretAccessKeyValue',
        'SessionToken': 'TargetAccount_SessionTokenValue',
    }
}
additional_account_assume_role_response = {
    'Credentials': {
        'AccessKeyId': 'AdditionalAccount_AccessKeyIdValue',
        'SecretAccessKey': 'AdditionalAccount_SecretAccessKeyValue',
        'SessionToken': 'AdditionalAccount_SessionTokenValue',
    }
}
target_account_session_called_with = {
    'aws_access_key_id': target_account_assume_role_response['Credentials']['AccessKeyId'],
    'aws_secret_access_key': target_account_assume_role_response['Credentials']['SecretAccessKey'],
    'aws_session_token': target_account_assume_role_response['Credentials']['SessionToken'],
}
additional_account_session_called_with = {
    'aws_access_key_id': additional_account_assume_role_response['Credentials']['AccessKeyId'],
    'aws_secret_access_key': additional_account_assume_role_response['Credentials']['SecretAccessKey'],
    'aws_session_token': additional_account_assume_role_response['Credentials']['SessionToken'],
}


@patch('boto3.client')
@patch('boto3.Session')
def test_create_session_with_assume_role(
    mock_session, mock_sts_client
):  # pylint: disable=unused-argument,redefined-outer-name

    # Configure the mock sts_client
    mock_session.return_value = MagicMock()
    mock_sts_client.return_value = MagicMock()
    mock_sts_client.return_value.assume_role.side_effect = [
        additional_account_assume_role_response,
        target_account_assume_role_response,
    ]

    create_session_with_assume_role(**additional_account_session_params)
    create_session_with_assume_role(**target_account_session_params)

    # verify input & output of create_session_with_assume_role
    mock_sts_client.return_value.assume_role.assert_called()
    assert mock_sts_client.return_value.assume_role.call_count == 2
    call_args_assume_role = mock_sts_client.return_value.assume_role.call_args_list
    assert call_args_assume_role[0] == ((), additional_account_assume_role_called_with)
    assert call_args_assume_role[1] == ((), target_account_assume_role_called_with)

    mock_session.assert_called()
    assert mock_session.call_count == 2
    call_args_session = mock_session.call_args_list
    assert call_args_session[0] == ((), additional_account_session_called_with)
    assert call_args_session[1] == ((), target_account_session_called_with)
