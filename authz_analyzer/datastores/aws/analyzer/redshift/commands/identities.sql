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
    LEFT JOIN pg_group ON pg_user.usesysid = ANY (pg_group.grolist)
UNION
SELECT
    user_id AS identity_id,
    user_name AS identity_name,
    'USER' AS identity_type,
    role_id AS granted_identity_id,
    role_name AS granted_identity_name,
    'ROLE' AS granted_identity_type,
    FALSE as is_admin
FROM
    svv_user_grants
UNION
SELECT
    role_id AS identity_id,
    role_name AS identity_name,
    'ROLE' AS identity_type,
    granted_role_id AS granted_identity_id,
    granted_role_name AS granted_identity_name,
    'ROLE' AS granted_identity_type,
    FALSE as is_admin
FROM
    svv_role_grants
WHERE
    identity_name != 'rdsdb';