import os
import pytest
import pathlib
import json
from authz_analyzer.writers.get_writers import get_writer
from authz_analyzer.writers.base_writers import OutputFormat
from authz_analyzer.datastores.aws.aws_authz_analyzer import AwsAuthzAnalyzer
from authz_analyzer.datastores.aws.services.s3.s3_service import S3ServiceType, S3_SERVICE_NAME
from authz_analyzer.datastores.aws.services.s3.s3_actions import S3Action
from authz_analyzer.datastores.aws.services.s3.bucket import S3Bucket
from authz_analyzer.datastores.aws.services.service_base import (
    register_service_action_by_name,
    register_service_resource_by_name,
    register_service_type_by_name,
)
from authz_analyzer.datastores.aws.utils.create_session import create_session_with_assume_role
from authz_analyzer.utils.logger import get_logger
from serde.json import to_json, from_dict


AWS_AUTHZ_ANALYZER_SATORI_DEV_JSON_FILE = pathlib.Path().joinpath(
    os.path.dirname(__file__), 'satori_dev_account_authz_analyzer.json'
)
AWS_AUTHZ_ANALYZER_SATORI_DEV_RESULT_JSON_FILE = pathlib.Path().joinpath(
    os.path.dirname(__file__), 'satori_dev_account_authz_analyzer_result.json'
)


@pytest.fixture
def register_services_for_deserialize_from_file(tmpdir):
    register_service_type_by_name(S3_SERVICE_NAME, S3ServiceType)
    register_service_action_by_name(S3_SERVICE_NAME, S3Action)
    register_service_resource_by_name(S3_SERVICE_NAME, S3Bucket)


@pytest.mark.skipif(
    not os.environ.get("AUTHZ_SATORI_DEV_ACCOUNT_TEST"),
    reason="not really a test, just pull latest satori dev account config and write it to file",
)
def test_aws_authz_analyzer_with_s3_write_satori_dev_account():
    aws_account_id = '105246067165'
    assume_role_name = 'LalonFromStage'
    session = create_session_with_assume_role(aws_account_id, assume_role_name)
    authz_analyzer = AwsAuthzAnalyzer.load(get_logger(False), aws_account_id, session, set([S3ServiceType()]))

    authz_analyzer_json = to_json(authz_analyzer)
    with open(AWS_AUTHZ_ANALYZER_SATORI_DEV_JSON_FILE, "w") as outfile:
        outfile.write(authz_analyzer_json)


@pytest.mark.skipif(
    not os.environ.get("AUTHZ_SATORI_DEV_ACCOUNT_TEST"),
    reason="not really a test, just pull latest satori dev account config and write it to file",
)
def test_aws_authz_analyzer_load_satori_dev_json_file(register_services_for_deserialize_from_file):
    with open(AWS_AUTHZ_ANALYZER_SATORI_DEV_JSON_FILE, "r") as f:
        authz_analyzer_json_from_file = json.load(f)
        authz_analyzer = from_dict(AwsAuthzAnalyzer, authz_analyzer_json_from_file)
        authz_analyzer_json_from_serde = json.loads(to_json(authz_analyzer))

        assert authz_analyzer_json_from_file == authz_analyzer_json_from_serde


@pytest.mark.skipif(
    not os.environ.get("AUTHZ_SATORI_DEV_ACCOUNT_TEST"),
    reason="not really a test, just pull latest satori dev account config and write it to file",
)
def test_aws_authz_analyzer_analyzed_permissions_satori_dev_json_file(register_services_for_deserialize_from_file):
    with open(AWS_AUTHZ_ANALYZER_SATORI_DEV_JSON_FILE, "r") as f:
        authz_analyzer_json_from_file = json.load(f)
        authz_analyzer: AwsAuthzAnalyzer = from_dict(AwsAuthzAnalyzer, authz_analyzer_json_from_file)
        writer = get_writer(AWS_AUTHZ_ANALYZER_SATORI_DEV_RESULT_JSON_FILE, OutputFormat.MULTI_JSON)
        authz_analyzer.write_permissions(get_logger(False), writer)
