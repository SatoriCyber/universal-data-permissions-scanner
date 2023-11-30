from universal_data_permissions_scanner.datastores.databricks.analyzer import DatabricksAuthzAnalyzer
from universal_data_permissions_scanner.datastores.databricks.service.authentication.authentication import (
    Authentication,
)


def test_databricks():
    authentication = Authentication.oauth_azure(
        "d339e9be-17e5-4986-a3ee-e0bcd648e692",
        "Ids8Q~y2DHZcJHHe4SMu2WWvz3cMlR~MqfX~JcaC",
        "eede60fb-12fd-41ff-92ab-7e6b6238afe0",
    )
    analyzer = DatabricksAuthzAnalyzer.connect(
        "https://adb-3183812393452943.3.azuredatabricks.net",
        authentication,
        "78588cf2-fd73-4995-9d9a-a2bdf17cd487",
    )
    analyzer.run()
