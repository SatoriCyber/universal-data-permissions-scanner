import os
import pathlib
import json
import pytest
from serde.json import to_json, from_dict

from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.utils.create_session import create_session_with_assume_role
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
    assume_role_name = 'SatoriScanner'
    session = create_session_with_assume_role(aws_account_id, assume_role_name)
    iam_entities = IAMEntities.load_for_account(get_logger(False), aws_account_id, session)
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
