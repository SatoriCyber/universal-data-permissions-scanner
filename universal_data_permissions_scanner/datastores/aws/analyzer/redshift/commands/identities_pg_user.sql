SELECT
    usesysid AS identity_id,
    usename AS identity_name,
    'USER' AS identity_type,
    grosysid AS granted_identity_id,
    groname AS granted_identity_name,
    'GROUP' AS granted_identity_type,
    usesuper as is_admin
FROM
    pg_user
    LEFT JOIN pg_group ON pg_user.usesysid = ANY (pg_group.grolist);