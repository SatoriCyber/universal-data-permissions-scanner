import os
import pathlib
import json
import pytest
from serde.json import to_json, from_dict

from authz_analyzer.datastores.aws.iam.iam_entities import IAMEntities
from authz_analyzer.datastores.aws.utils.create_session import create_session_with_assume_role
from authz_analyzer.utils.logger import get_logger


IAM_ENTITIES_SATORI_DEV_JSON_FILE = pathlib.Path().joinpath(
    os.path.dirname(__file__), 'satori_dev_account_iam_entities.json'
)


@pytest.mark.skipif(
    not os.environ.get("AUTHZ_SATORI_DEV_ACCOUNT_TEST"),
    reason="not really a test, just pull latest satori dev account config and write it to file",
)
def test_iam_entities_write_satori_dev_account():
    aws_account_id = '105246067165'
    assume_role_name = 'LalonFromStage'
    session = create_session_with_assume_role(aws_account_id, assume_role_name)
    iam_entities = IAMEntities.load(get_logger(False), aws_account_id, session)

    iam_entities_json = to_json(iam_entities)
    with open(IAM_ENTITIES_SATORI_DEV_JSON_FILE, "w", encoding="utf-8") as outfile:
        outfile.write(iam_entities_json)


@pytest.mark.skipif(
    not os.environ.get("AUTHZ_SATORI_DEV_ACCOUNT_TEST"),
    reason="not really a test, just pull latest satori dev account config and write it to file",
)
def test_iam_entities_load_satori_dev_json_file():
    with open(IAM_ENTITIES_SATORI_DEV_JSON_FILE, "r", encoding="utf-8") as file:
        iam_entities_json_from_file = json.load(file)
        iam_entities = from_dict(IAMEntities, iam_entities_json_from_file)
        iam_entities_json_from_serde = json.loads(to_json(iam_entities))

        assert iam_entities_json_from_file == iam_entities_json_from_serde


@pytest.mark.skipif(
    not os.environ.get("AUTHZ_SATORI_DEV_ACCOUNT_TEST"),
    reason="not really a test, just pull latest satori dev account config and write it to file",
)
def test_iam_entities_satori_dev_build_principals_network_graph():
    logger = get_logger(False)
    iam_entities: IAMEntities = IAMEntities.load_from_json_file(logger, IAM_ENTITIES_SATORI_DEV_JSON_FILE)
    iam_entities.build_principal_network_graph(logger)
