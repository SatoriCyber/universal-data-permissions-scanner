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