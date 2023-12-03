SELECT
    user_id AS identity_id,
    user_name AS identity_name,
    'USER' AS identity_type,
    role_id AS granted_identity_id,
    role_name AS granted_identity_name,
    'ROLE' AS granted_identity_type,
    FALSE as is_admin
FROM
    svv_user_grants;