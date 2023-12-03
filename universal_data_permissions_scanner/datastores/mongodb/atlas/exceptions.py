from universal_data_permissions_scanner.datastores.mongodb.atlas.service_model import ActionEntry


class ActionResourcesNotFoundException(Exception):
    def __init__(self, action: ActionEntry) -> None:
        self.action = action
        super().__init__(f"Resources not found for action: {self.action}")
