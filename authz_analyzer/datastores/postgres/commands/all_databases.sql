SELECT
    datname
FROM
    pg_database
where
    datistemplate = false