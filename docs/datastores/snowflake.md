Snowflake implements a role-based access control (RBAC) model to manage access to data assets. Roles are granted with privileges on data assets and users are assigned to roles, which can be organized hierarchically. All users are assigned to the `PUBLIC` role by default.

## Setup Access to Scan a Snowflake Account
1. Create a role for authz-analyzer using the following command:
```
CREATE ROLE AUTHZ_ANALYZER_ROLE;
```
2. Grant privileges to the role you created using the following command:
```
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE AUTHZ_ANALYZER_ROLE;
GRANT USAGE ON WAREHOUSE <REPLACE_WITH_WAREHOUSE_NAME> TO ROLE AUTHZ_ANALYZER_ROLE;
GRANT IMPORT SHARE ON ACCOUNT TO AUTHZ_ANALYZER_ROLE;
```
3. Create a user for authz-analyzer and assign it to the role you created using the following commands:
```
CREATE USER AUTHZ_ANALYZER password='<REPLACE_WITH_A_STRONG_PASSWORD>' default_role = AUTHZ_ANALYZER_ROLE;
GRANT ROLE AUTHZ_ANALYZER_ROLE TO USER AUTHZ_ANALYZER;
```

## Scanning Snowflake
```
authz-analyzer snowflake \
    --account <REPLACE_WITH_ACCOUNT> \
    --username <USERNAME> \
    --password <PASSWORD> 
```

## Known Limitations
The following Snowflake features are not currently supported by authz-analyzer:

* SNOWFLAKE database roles
* Permissions on objects to a share via a database role