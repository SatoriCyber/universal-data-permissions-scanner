SELECT
    grantee_name as role,
    PRIVILEGE,
    concat(TABLE_CATALOG, '.', table_schema, '.', name) as table_name
from
    snowflake.account_usage.grants_to_roles
where
    GRANTED_ON in ('TABLE', 'VIEW')
    and DELETED_ON is not null
