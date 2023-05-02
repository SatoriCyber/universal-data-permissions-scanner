from typing import Any, Dict, Optional, Set

from aws_ptrp import AwsPtrp
from aws_ptrp.actions.aws_actions import AwsActions
from aws_ptrp.iam.iam_entities import IAMEntities
from aws_ptrp.iam_identity_center.iam_identity_center_entities import IamIdentityCenterEntities
from aws_ptrp.principals.aws_principals import AwsPrincipals
from aws_ptrp.resources.account_resources import AwsAccountResources
from aws_ptrp.services.assume_role.assume_role_service import AssumeRoleService
from aws_ptrp.services.federated_user.federated_user_service import FederatedUserService
from aws_ptrp.services.service_resource_type import ServiceResourceType
from serde.de import from_dict

from universal_data_permissions_scanner.utils.logger import get_logger


def load_aws_ptrp_from_dict(
    iam_entities_dict: Dict[Any, Any],
    target_account_resources_dict: Dict[Any, Any],
    iam_identity_center_entities_dict: Optional[Dict[Any, Any]],
    resource_service_types_to_load: Set[ServiceResourceType],
) -> AwsPtrp:
    # Load iam_entities
    iam_entities: IAMEntities = from_dict(IAMEntities, iam_entities_dict)  # type: ignore

    # Load AWS target account resources
    target_account_resources: AwsAccountResources = from_dict(AwsAccountResources, target_account_resources_dict)  # type: ignore
    target_account_resources.update_services_from_iam_entities(
        get_logger(False), iam_entities, resource_service_types_to_load
    )
    ## valid that all resources are belong to the target aws account id (except the assume-role, federated-user)
    services_not_to_valid = set([AssumeRoleService(), FederatedUserService()])
    for resource_service_type, target_account_service_resources in target_account_resources.account_resources.items():
        if resource_service_type not in services_not_to_valid:
            for target_account_service_resource in target_account_service_resources:
                assert (
                    target_account_service_resource.get_resource_account_id() == target_account_resources.aws_account_id
                )

    # Load AWS actions
    aws_actions = AwsActions.load(get_logger(False), resource_service_types_to_load)  # type: ignore

    # Load AWS principals
    aws_principals = AwsPrincipals.load(get_logger(False), iam_entities, target_account_resources)

    if iam_identity_center_entities_dict:
        iam_identity_center_entities = from_dict(
            IamIdentityCenterEntities, iam_identity_center_entities_dict
        )  # type: ignore
    else:
        iam_identity_center_entities = None

    return AwsPtrp(
        aws_actions=aws_actions,
        aws_principals=aws_principals,
        iam_entities=iam_entities,
        target_account_resources=target_account_resources,
        iam_identity_center_entities=iam_identity_center_entities,  # type: ignore
    )
