select
    grantor,
    grantee,
    table_catalog as db,
    table_schema as schema,
    table_name as table,
    privilege_type
from
    information_schema.table_privileges