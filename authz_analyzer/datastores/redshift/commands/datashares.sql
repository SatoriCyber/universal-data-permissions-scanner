select
    share_name,
    share_id,
    producer_account,
    producer_namespace
from
    pg_catalog.svv_datashares
where
    share_type == 'OUTBOUND'