Snowflake implements a role-based access control (RBAC) model to manage access to data assets. Roles are granted with privileges on data assets and users are assigned to roles, which can be organized hierarchically. All users are assigned to the `PUBLIC` role by default.

## Setup Access to Scan a Snowflake Account
1. Create a role for universal-data-permissions-scanner using the following command:
```
CREATE ROLE UDPS_ROLE;
```
2. Grant privileges to the role you created using the following command:
```
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE UDPS_ROLE;
GRANT USAGE ON WAREHOUSE <REPLACE_WITH_WAREHOUSE_NAME> TO ROLE UDPS_ROLE;
GRANT IMPORT SHARE ON ACCOUNT TO UDPS_ROLE;
```
3. Create a user for universal-data-permissions-scanner and assign it to the role you created using the following commands:
```
CREATE USER UDPS password='<REPLACE_WITH_A_STRONG_PASSWORD>' default_role = UDPS_ROLE;
GRANT ROLE UDPS_ROLE TO USER UDPS;
```

## Scanning Snowflake
```
udps snowflake \
    --account <REPLACE_WITH_ACCOUNT> \
    --username <USERNAME> \
    --password <PASSWORD> 
```

## Known Limitations
The following Snowflake features are not currently supported by universal-data-permissions-scanner:

* SNOWFLAKE database roles
* Permissions on objects to a share via a database role