Databricks has two locations where identity is managed:
* Account
* Workspace (deprecated)
There are two types of identities:
* Users
* service principals
Users and service principals can be assigned to groups. Groups can be assigned to other groups.
Users, service principals and groups are assigned to workspaces, workspaces are assigned to unity-catalog.
Unity-catalog manage access to data assets.
Each asset has ownership, which grants full permission.
Assets are hierarchical, so permissions can be inherited from parent assets.
For example, a users can be granted select on a catalog, all tables which belong to the catalog will inherit the permission.

## Setup Access to Scan a Databricks:
1. For a user with admin access to the account and which is member of the unity-catalog, login to a workspace, click on the user icon in the top right corner and select "User Settings" -> "Access Tokens" -> "Generate New Token". Copy the generated token.

## Scanning databricks
```
udps databricks \
    --host <WORKSPACE URL> \
    --api_key <API_TOKEN> \
```
