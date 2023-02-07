SELECT
    datname,
    datallowconn
FROM
    pg_database
where
    datistemplate = false;