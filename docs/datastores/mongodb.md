authz-analyzer supports two types of MongoDB implementations:

* MongoDB Atlas
* Standalone MongoDB Cluster

## MongoDB Atlas

MongoDB Atlas is a managed MongoDB service. It provides managed clusters and a host of related services. authz-analyzer currently supports scanning of MongoDB cluster permissions. MongoDB Atlas implements a role-based access control (RBAC) model to manage access to data assets.

Atlas has two types of users:

* Database Users - users that have access to an Atlas-managed MongoDB cluster. Database users may have privileges granted to them or they may be assigned with a built-in or user-defined role. Roles can be organized hierarchically.
* Organization Users - users that have access to the Atlas console. Organization users are assigned to organization roles which define their permissions and resources like projects and clusters they can access.

### Setup Access to Scan a MongoDB Atlas Cluster

To enable universal-data-permissions-scanner to scan the list of users, roles and permissions perform the following steps:
1. Create an organization API Key in the Atlas management console.
2. Grant the `Organization Read Only` role to the API key you created
3. Copy the Public and Private keys and store them for later use.

To enable universal-data-permissions-scanner to scan the list of databases and collections in a MongoDB cluster perform the following steps:
1. Create a custom role.
2. Grant the `listDatabases` action to the role.
3. Grant the `listCollections` action on each database in the cluster to the role.
4. Create a database user and assign it to the custom role you created.

### Scanning a MongoDB Atlas Cluster
```
udps atlas \
    --public_key <PUBLIC KEY> \
    --private_key <PRIVATE KEY> \
    --username <DB USER> \
    --password <DB USER PASSWORD> \
    --cluster_name <CLUSTER> \
    --project <PROJECT>
```

## Standalone MongoDB Cluster
MongoDB implements a role-based access control (RBAC) model to manage access to data assets. Users are assigned with roles which have privileges. Role can be built-it or user-defined, and organized hierarchically. Roles that are assigned to the admin database have access across all databases while roles that are assigned to a specific databases have access only to those databases.

### Setup Access to Scan a Standalone MongoDB Cluster
1. Create a role for universal-data-permissions-scanner using the following command:
```
db.createRole(
    {
        role:"udps",
        privileges: [
            {
                resource: {
                    db: "",
                    collection: ""
                },
                actions: ["listDatabases", "listCollections", "viewRole", "viewUser"]
            }
        ],
        roles: []
    }
)    
```

2. Create a user for universal-data-permissions-scanner using the following command:
```
db.createUser(
    {
        user: "udps_user",
        roles: ["udps"],
        pwd: "<password>"
    }
) 
```

### Scanning a Standalone MongoDB Cluster
```
udps mongodb \
    --host <CLUSTER HOSTNAME> \
    --username <USERNAME> \
    --password <PASSWORD>
```

## Known Limitations
The following MongoDB features are not currently supported by universal-data-permissions-scanner:

* Data API
* Cloud users
* LDAP Users
* Federated users
