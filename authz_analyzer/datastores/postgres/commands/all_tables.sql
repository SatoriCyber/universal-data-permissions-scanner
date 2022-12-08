with all_db as (
    SELECT
        CONCAT(table_schema, '.', table_name) as schema_table_name
    FROM
        information_schema.tables
    ORDER BY
        table_schema,
        table_name
),
current_db as (
    select
        current_database as db
    from
        current_database()
)
SELECT
    CONCAT(schema_table_name, '.', db) as table_name
from
    all_db,
    current_db