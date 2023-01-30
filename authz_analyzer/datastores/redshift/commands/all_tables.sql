select
    table_catalog as db,
    table_schema as schema,
    table_name as name,
    table_type as type
from
    information_schema.tables