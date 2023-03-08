SELECT
    relname as table_name,
    nspname as schema_name,
    relkind as type,
    rolname as owner,
    relacl as acl
FROM
    pg_namespace
    JOIN pg_class ON (relnamespace = pg_namespace.oid)
    join pg_roles on (pg_class.relowner = pg_roles.oid)
where
    relkind in ('t', 'r', 't', 'v', 'm', 'f', 'p');