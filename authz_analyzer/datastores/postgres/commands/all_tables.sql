with all_db as (
    SELECT
        table_schema,
        table_name
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
    current_db.db,
    all_db.table_schema,
    all_db.table_name
from
    all_db,
    current_db