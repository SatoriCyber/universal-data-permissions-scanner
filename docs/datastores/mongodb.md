The project supports two types of MongoDB implementations:

* MongoDB Atlas
* MongoDB cluster


**MongoDB Atlas**

The Atlas is a managed service for MongoDB, it provides a managed cluster, and a managed user management.
The Authz-Analyzer will scan only a single cluster.
Atlas has two types of users:

* Database User - A user that has access to a cluster. Database user may have privileges assigned to it, or it may have a role assigned to it.
Two type of roles:
    * Built-in roles - defined by MongoDB.
    * User defined roles - defined by the user.
Roles can be assigned to other roles, creating a hierarchy of roles.
* Organization user  - A user that has access to Atlas. Organization users are assigned with a role.

An Organization role has scope:

  * Organization scope - which provides access across projects.
  * Project scope - which provides access to a specific project.
A user can be part of a team, and the team can have a role.

There are ways to manage those users:

* Database user:
    * Local - Users which are configured directly on Atlas.
    * LDAP - The cluster will query the LDAP server for authentication.
    * Cloud - Use AWS IAM role to authenticate.
* Organization user:
    * Local users - Users which are configured directly on Atlas.
    * Federated users - Users which are configured on the organization's SAML provider.

MongoDB also has a notion of Data API, which isn't supported by this project.

**MongoDB cluster**

A MongoDB cluster is a set of servers that store data.
MongoDB implements RBAC model.
Users are assigned with roles which have privileges.
Roles which are assigned to the admin database have access across all databases.
Roles which are assigned to a specific database have access only to that database.
There are roles which are built-in, and roles which are defined by the user.
Roles can be assigned to other roles, creating a hierarchy of roles.

## Setup Access to Scan MongoDB Atlas
authz-analyzer needs the following permissions:
Atlas level:
```
Organization read only.
```
For each cluster create a database user with the following permissions:
```
list databases
```
For each database in the cluster assign:
```
list collections
```


## Setup Access to Scan MongoDB cluster
authz-analyzer needs the following permissions:
```
db.createRole(
        {
            role:"authz_analyzer_role",
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

        db.createUser(
            {
                user: "authz_analyzer",
                roles: ["authz_analyzer_role"],
                pwd: "<password>"
            }
        ) 
```

## Scanning MongoDB Atlas
```
authz-analyzer atlas --public_key <REPLACE WITH ATLAS ADMIN API PUBLIC KEY> --private_key <REPLACE WITH ATLAS ADMIN API PRIVATE KEY> --username <REPLACE WITH CLUSTER USER> --password <REPLACE WITH CLUSTER PASSWORD> --cluster_name <REPLACE WITH CLUSTER NAME> --project <REPLACE WITH PROJECT NAME>
```

## Scanning MongoDB cluster
```
authz-analyzer mongodb --host <REPLACE WITH HOST> --username <REPLACE WITH CLUSTER USER> --password <REPLACE WITH CLUSTER PASSWORD>
```

## Known Limitations
Data API

Cloud users

LDAP Users

Federated users
