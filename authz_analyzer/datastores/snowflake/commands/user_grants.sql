with users_grants as (
    SELECT
        GRANTEE_NAME as user,
        ROLE as role
    FROM
        snowflake.account_usage.grants_to_users
    where
        deleted_on is null
),
users as (
    SELECT
        NAME as user,
        email
    from
        snowflake.account_usage.users
)
select
    users_grants.user as user,
    users_grants.role as role,
    users.email as email
from
    users_grants
    inner join users on users_grants.user = users.user
order by
    users_grants.user