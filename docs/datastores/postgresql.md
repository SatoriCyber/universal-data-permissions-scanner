PostgreSQL implements a role-based access control (RBAC) model to manage access to data assets. In PostgreSQL there is no dedicated user object, instead roles that have the login property are used by users to login to the database. Roles can be organized hierarchically. All users are assigned to the `PUBLIC` role by default.

## Setup Access to Scan a PostgreSQL Server:
1. Create a role for authz-analyzer using the following command: 
```
CREATE ROLE authz_analyzer NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT LOGIN NOREPLICATION NOBYPASSRLS PASSWORD '<REPLACE_WITH_A_STRONG_PASSWORD>';
```
2. For each database on the server, grant permissions for the authz-analyzer role using the following command:
```
GRANT SELECT ON TABLE information_schema.tables TO authz_analyzer;
GRANT SELECT ON TABLE information_schema.table_privileges TO authz_analyzer;
```

1. For deployments which are not AWS RDS add the following permissions:
```
GRANT SELECT ON TABLE pg_database TO authz_analyzer;
GRANT SELECT ON TABLE pg_catalog.pg_roles TO authz_analyzer;
```

## Scanning a PostgreSQL Server
```
authz-analyzer postgres \
    --host <HOST> \
    --username <USERNAME> \
    --password <PASSWORD> \
    --dbname <DB>
```
