SELECT
    NAME as granted_to,
    GRANTEE_NAME as role
    
FROM
    snowflake.account_usage.grants_to_roles
where
    deleted_on is null
    and GRANTED_ON = 'ROLE'
    and privilege = 'USAGE'