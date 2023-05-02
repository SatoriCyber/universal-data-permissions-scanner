import json
import os
import pathlib
from typing import List

import pytest
from aws_ptrp.ptrp_models import AwsPtrpLine
from serde import to_dict
from serde.de import from_dict

from universal_data_permissions_scanner.datastores.aws.analyzer.exporter import AWSAuthzAnalyzerExporter
from universal_data_permissions_scanner.models.model import AuthzEntry
from tests.mocks.mock_writers import MockWriter

RESOURCES_INPUT_DIR = pathlib.Path().joinpath(os.path.dirname(__file__), 'exporter_test_inputs')


def get_resolve_permissions_test_inputs() -> List[str]:
    ret = []
    assert os.path.isdir(RESOURCES_INPUT_DIR)
    for root, _dirs, files in os.walk(RESOURCES_INPUT_DIR):
        for file in files:
            ret.append(os.path.relpath(os.path.join(root, file), RESOURCES_INPUT_DIR))
    return ret


@pytest.mark.parametrize("test_input", get_resolve_permissions_test_inputs())
def test_exporter(test_input: str):
    test_file_path = os.path.join(RESOURCES_INPUT_DIR, test_input)
    mocked_writer = MockWriter.new()
    exporter: AWSAuthzAnalyzerExporter = AWSAuthzAnalyzerExporter(writer=mocked_writer.get())

    with open(test_file_path, "r", encoding="utf-8") as json_file_r:
        json_loaded = json.load(json_file_r)
        ptrp_line: AwsPtrpLine = from_dict(AwsPtrpLine, to_dict(json_loaded["ptrp_line"]))  # type: ignore
        exporter.export_entry_from_ptrp_line(ptrp_line)
        authz_entry: AuthzEntry = from_dict(AuthzEntry, to_dict(json_loaded["authz_entry"]))  # type: ignore
        mocked_writer.assert_write_entry_called_once_with(authz_entry)
