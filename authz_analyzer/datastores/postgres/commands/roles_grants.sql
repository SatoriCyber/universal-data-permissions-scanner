select
    grantor,
    grantee,
    concat(
        table_catalog,
        '.',
        table_schema,
        '.',
        table_name
    ) as table_name,
    privilege_type
from
    information_schema.table_privileges