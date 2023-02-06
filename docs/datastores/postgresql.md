Postgres uses the RBAC to manage access to data assets. There are no notion of users, there are only roles, role can have a login property.

Roles can be assigned to other roles, creating a hierarchy of roles.
Roles can't be circularly assigned to each other.
All users has the `PUBLIC` role, which is the default role for all users.
Superuser role have access to all data assets.

## Setup Access to Scan Postgres
authz-analyzer needs the following permissions:
```
-- create a new role for ‘authz_analyzer’
CREATE ROLE authz_analyzer NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT LOGIN NOREPLICATION NOBYPASSRLS PASSWORD '<REPLACE_WITH_A_STRONG_PASSWORD>';

-- for each DB at the postgres cluster:
GRANT SELECT ON TABLE pg_database TO authz_analyzer;
GRANT SELECT ON TABLE information_schema.tables TO authz_analyzer;
GRANT SELECT ON TABLE information_schema.table_privileges TO authz_analyzer;
GRANT SELECT ON TABLE pg_catalog.pg_roles TO authz_analyzer;
    
```

## Scanning Postgres
Postgres needs an initial database to connect to.
The following command will scan the Postgres database and generate a report:
```
authz-analyzer postgres --user <REPLACE_WITH_USER> --password <REPLACE_WITH_PASSWORD> --host <REPLACE_WITH_HOST> --dbname <REPLACE_WITH_DBNAME>
```

## Known Limitations
