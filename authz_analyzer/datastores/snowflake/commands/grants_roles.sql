SELECT
    NAME as name,
    GRANTEE_NAME as grantee_name,
    PRIVILEGE as privilege,
    concat(TABLE_CATALOG, '.', table_schema, '.', name) as table_name,
    GRANTED_ON as granted_on
FROM
    snowflake.account_usage.grants_to_roles
where
    deleted_on is null
    and GRANTED_ON in ('TABLE', 'VIEW', 'MATERIALIZED VIEW', 'ROLE')
order by
    table_name