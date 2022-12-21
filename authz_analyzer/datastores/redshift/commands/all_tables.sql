with all_db as (
    SELECT
        CONCAT(CONCAT(schemaname, '.'), tablename) as schema_table_name
    FROM
        PG_TABLE_DEF
    ORDER BY
        schemaname,
        tablename
),
     current_db as (
         select
             current_database as db
         from
             current_database()
     )
SELECT
    CONCAT(CONCAT(schema_table_name, '.'), db) as table_name
from
    all_db,
    current_db;
