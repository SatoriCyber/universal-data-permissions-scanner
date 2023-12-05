from universal_data_permissions_scanner.datastores.mongodb.atlas.service_model import ActionEntry

from universal_data_permissions_scanner.datastores.mongodb.service_model import ResourceEntry


class ActionResourcesNotFoundException(Exception):
    def __init__(self, action: ActionEntry) -> None:
        self.action = action
        super().__init__(f"Resources not found for action: {self.action}")


class ActionResourceNotFoundException(Exception):
    def __init__(self, resource: ResourceEntry) -> None:
        self.resource = resource
        super().__init__(f"Collection not found for resource: {self.resource}")
