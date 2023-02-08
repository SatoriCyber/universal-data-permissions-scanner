-- identities(user,group,role) privilege to asset
SELECT
    'UNKNOWN' AS grantor,
    identity_id AS grantee,
    namespace_name AS schema_name,
    relation_name AS table_name,
    privilege_type
FROM svv_relation_privileges
--WHERE identity_name != 'public';
