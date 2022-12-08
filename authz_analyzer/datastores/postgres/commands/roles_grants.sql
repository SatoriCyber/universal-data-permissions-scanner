with table_priv as (
    SELECT
        grantor,
        grantee,
        table_schema,
        table_name,
        privilege_type
    FROM
        information_schema.table_privileges
),
current_db as (
    select
        current_database as db
    from
        current_database()
)
select
    grantor,
    grantee,
    concat(db, '.', table_schema, '.', table_name) as table_name,
    privilege_type
from
    table_priv,
    current_db