import os
import pytest
import pathlib
import json
from authz_analyzer.utils.aws.aws_authz_analyzer import AwsAuthzAnalyzer
from authz_analyzer.utils.aws.s3.bucket import S3ServiceType
from authz_analyzer.utils.aws.create_session import create_session_with_assume_role
from authz_analyzer.utils.logger import get_logger
from serde.json import to_json, from_dict


AWS_AUTHZ_ANALYZER_SATORI_DEV_JSON_FILE = pathlib.Path().joinpath(
    os.path.dirname(__file__), 'satori_dev_account_authz_analyzer.json'
)


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
def test_authz_analyzer_load_satori_dev_json_file():
    with open(AWS_AUTHZ_ANALYZER_SATORI_DEV_JSON_FILE, "r") as f:
        authz_analyzer_json_from_file = json.load(f)
        authz_analyzer = from_dict(AwsAuthzAnalyzer, authz_analyzer_json_from_file)
        authz_analyzer_json_from_serde = json.loads(to_json(authz_analyzer))

        assert authz_analyzer_json_from_file == authz_analyzer_json_from_serde


# @pytest.mark.skipif(
#     not os.environ.get("AUTHZ_SATORI_DEV_ACCOUNT_TEST"),
#     reason="not really a test, just pull latest satori dev account config and write it to file",
# )
# def test_iam_entities_satori_dev_build_principals_network_graph():
#     logger = get_logger(False)
#     iam_entities: IAMEntities = IAMEntities.load_from_json_file(
#         logger, IAM_ENTITIES_SATORI_DEV_JSON_FILE
#     )
#     iam_entities.build_principal_network_graph(logger)
