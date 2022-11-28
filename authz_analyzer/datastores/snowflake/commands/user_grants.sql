SELECT
    GRANTEE_NAME as user,
    ROLE as role
FROM
    snowflake.account_usage.grants_to_users
where
    deleted_on is null
order by GRANTEE_NAME    

