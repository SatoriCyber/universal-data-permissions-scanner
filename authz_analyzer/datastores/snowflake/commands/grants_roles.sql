SELECT
    GRANTEE_NAME as grantee_name,
    PRIVILEGE as privilege,
    TABLE_CATALOG as db,
    TABLE_SCHEMA as schema,
    name as resource_name,
    GRANTED_ON as granted_on
FROM
    snowflake.account_usage.grants_to_roles
where
    deleted_on is null
    and GRANTED_ON in ('TABLE', 'VIEW', 'MATERIALIZED VIEW', 'ROLE')
order by
    grantee_name,
    db,
    schema,
    resource_name