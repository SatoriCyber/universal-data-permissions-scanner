Snowflake uses the RBAC to manage access to data assets. Users are assigned to roles in order to access data, users don't have direct privileges on data assets.

Roles can be assigned to other roles, creating a hierarchy of roles.
Roles can't be circularly assigned to each other.
All users has the `PUBLIC` role, which is the default role for all users.

## Setup Access to Scan Snowflake
authz-analyzer needs the following permissions:
```
-- create a new role;
CREATE ROLE AUTHZ_SCANNER_ROLE;

-- grant privileges on a database
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE AUTHZ_SCANNER_ROLE;
GRANT USAGE ON WAREHOUSE <REPLACE_WITH_WAREHOUSE_NAME> TO ROLE AUTHZ_SCANNER_ROLE;

--- grant privileges on shares.
GRANT IMPORT SHARE ON ACCOUNT TO AUTHZ_SCANNER_ROLE;

-- create a user
CREATE USER AUTHZ_SCANNER password='<REPLACE_WITH_A_STRONG_PASSWORD>' default_role = AUTHZ_SCANNER_ROLE;

-- assign role 'AUTHZ_SCANNER_ROLE' to the new user
GRANT ROLE AUTHZ_SCANNER_ROLE TO USER AUTHZ_SCANNER;
```

## Scanning Snowflake
The following command will scan the Snowflake database and generate a report:
```
authz-analyzer snowflake --user <REPLACE_WITH_USER> --password <REPLACE_WITH_PASSWORD> --account <REPLACE_WITH_ACCOUNT> --host <REPLACE_WITH_HOST>
```

## Known Limitations
Snowflake DB roles aren't supported.
Datashare with permissions to DB Role isn't supported