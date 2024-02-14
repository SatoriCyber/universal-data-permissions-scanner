from universal_data_permissions_scanner.datastores.mongodb.atlas.service_model import (
    CustomRoleEntry,
)

from universal_data_permissions_scanner.datastores.mongodb.atlas.model import (
    CustomRole,
    Action,
    Resource,
    Permission,
)


def test_atlas_build_custom_role_from_response():
    cluster_db_to_collections_mapping = {
        "test": ["test_collection"],
        "test2": ["test_collection2"],
    }

    custom_role_entry = CustomRoleEntry(
        {  # pyright: ignore [reportGeneralTypeIssues]
            'actions': [  # type: ignore
                {'action': 'OUT_TO_S3', 'resources': [{'cluster': True}]},
                {'action': 'FIND', 'resources': [{'collection': 'test_collection2', 'db': 'test2'}]},
                {'action': 'DROP_DATABASE', 'resources': [{'collection': '', 'db': 'test'}]},
            ],
            'inheritedRoles': [],
            'roleName': 'bla',
        }
    )

    res = CustomRole.build_custom_role_from_response(
        entry=custom_role_entry, project_dbs_to_collections=cluster_db_to_collections_mapping
    )
    expected = CustomRole(
        name='bla',
        actions={
            Action(resource=Resource(collection='test_collection', database='test'), permission=Permission.OUT_TO_S3),
            Action(resource=Resource(collection='test_collection2', database='test2'), permission=Permission.OUT_TO_S3),
            Action(resource=Resource(collection='test_collection2', database='test2'), permission=Permission.FIND),
            Action(resource=Resource(collection='test_collection2', database='test2'), permission=Permission.FIND),
            Action(resource=Resource(collection='', database='test'), permission=Permission.DROP_DATABASE),
        },
        inherited_roles=set(),
    )

    assert res == expected
