select
    share_id,
    share_name,
    source_database
from
    pg_catalog.svv_datashares
where
    share_type = 'OUTBOUND'