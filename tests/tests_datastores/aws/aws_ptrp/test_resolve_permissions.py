import json
import os
import pathlib
from dataclasses import dataclass, field
from typing import Any, List, Set

import pytest
from aws_ptrp import AwsPtrp
from aws_ptrp.iam.iam_roles import IAMRole
from aws_ptrp.ptrp_models.ptrp_model import AwsPtrpLine
from aws_ptrp.services import (
    ServiceResourceType,
    register_service_action_by_name,
    register_service_action_type_by_name,
    register_service_resource_by_name,
    register_service_resource_type_by_name,
)
from aws_ptrp.services.assume_role.assume_role_actions import AssumeRoleAction
from aws_ptrp.services.assume_role.assume_role_service import ROLE_TRUST_SERVICE_NAME, AssumeRoleService
from aws_ptrp.services.federated_user.federated_user_actions import FederatedUserAction
from aws_ptrp.services.federated_user.federated_user_resources import FederatedUserResource
from aws_ptrp.services.federated_user.federated_user_service import FEDERATED_USER_SERVICE_NAME, FederatedUserService
from aws_ptrp.services.s3.bucket import S3Bucket
from aws_ptrp.services.s3.s3_actions import S3Action
from aws_ptrp.services.s3.s3_service import S3_SERVICE_NAME, S3Service
from serde.se import to_dict

from universal_data_permissions_scanner.utils.logger import get_logger
from tests.tests_datastores.aws.aws_ptrp.utils.aws_ptrp_load_from_dict import load_aws_ptrp_from_dict

RESOURCES_INPUT_DIR = pathlib.Path().joinpath(os.path.dirname(__file__), 'resolve_permissions_test_inputs')


@pytest.fixture
def register_services_for_deserialize_from_file():
    # add resolvers here action the type and the service
    register_service_action_by_name(S3_SERVICE_NAME, S3Action)
    register_service_resource_by_name(S3_SERVICE_NAME, S3Bucket)
    register_service_action_by_name(ROLE_TRUST_SERVICE_NAME, AssumeRoleAction)
    register_service_resource_by_name(ROLE_TRUST_SERVICE_NAME, IAMRole)
    register_service_action_by_name(FEDERATED_USER_SERVICE_NAME, FederatedUserAction)
    register_service_resource_by_name(FEDERATED_USER_SERVICE_NAME, FederatedUserResource)
    register_service_action_type_by_name(S3_SERVICE_NAME, S3Service)
    register_service_resource_type_by_name(S3_SERVICE_NAME, S3Service)
    register_service_action_type_by_name(ROLE_TRUST_SERVICE_NAME, AssumeRoleService)
    register_service_resource_type_by_name(ROLE_TRUST_SERVICE_NAME, AssumeRoleService)
    register_service_action_type_by_name(FEDERATED_USER_SERVICE_NAME, FederatedUserService)
    register_service_resource_type_by_name(FEDERATED_USER_SERVICE_NAME, FederatedUserService)


@dataclass
class CompareAwsPtrpLines:
    expected_output: List[Any]
    test_output: List[AwsPtrpLine] = field(default_factory=list)

    def append_test_aws_ptrp_line(self, line: AwsPtrpLine):
        self.test_output.append(line)

    def get_test_output_dict(self) -> List[Any]:
        self.test_output.sort()
        return [to_dict(line) for line in self.test_output]

    def is_equal(self) -> bool:
        return self.expected_output == self.get_test_output_dict()


def get_resolve_permissions_test_inputs() -> List[str]:
    ret = []
    assert os.path.isdir(RESOURCES_INPUT_DIR)
    for root, _dirs, files in os.walk(RESOURCES_INPUT_DIR):
        for file in files:
            ret.append(os.path.relpath(os.path.join(root, file), RESOURCES_INPUT_DIR))
    return ret


@pytest.mark.parametrize("test_input", get_resolve_permissions_test_inputs())
def test_aws_ptrp_resolve_permissions_flows(
    register_services_for_deserialize_from_file,
    test_input: str,
):  # pylint: disable=unused-argument,redefined-outer-name
    should_override_output = os.environ.get("TEST_PTRP_RESOLVE_PERMISSIONS_OVERRIDE_OUTPUT", "False").lower() == "true"
    test_file_path = os.path.join(RESOURCES_INPUT_DIR, test_input)

    with open(test_file_path, "r", encoding="utf-8") as json_file_r:
        json_loaded = json.load(json_file_r)
        resource_service_types_to_load: Set[ServiceResourceType] = set(
            [AssumeRoleService(), FederatedUserService(), S3Service()]
        )
        ptrp: AwsPtrp = load_aws_ptrp_from_dict(
            json_loaded['input']['iam_entities'],
            json_loaded['input']['target_account_resources'],
            json_loaded['input'].get('iam_identity_center_entities', None),
            resource_service_types_to_load,
        )

        expected_output: List[Any] = json_loaded['output']
        compare_lines = CompareAwsPtrpLines(expected_output=expected_output)
        ptrp.resolve_permissions(get_logger(False), compare_lines.append_test_aws_ptrp_line)
        if not should_override_output:
            assert compare_lines.is_equal()

    if should_override_output:
        json_loaded['output'] = compare_lines.get_test_output_dict()
        to_write: str = json.dumps(json_loaded, indent=4)
        with open(test_file_path, "w", encoding="utf-8") as json_file_w:
            json_file_w.write(to_write)
