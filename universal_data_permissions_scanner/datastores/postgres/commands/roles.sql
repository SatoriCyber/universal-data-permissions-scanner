SELECT
    r.rolname as username,
    r.rolsuper as superuser,
    r1.rolname as "role",
    r.rolcanlogin as login
FROM
    pg_catalog.pg_roles r FULL
    OUTER JOIN pg_catalog.pg_auth_members m ON (m.member = r.oid) FULL
    OUTER JOIN pg_roles r1 ON (m.roleid = r1.oid)