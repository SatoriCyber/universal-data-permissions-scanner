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
        email,
        default_role
    from
        snowflake.account_usage.users
)
select
    users.user as user,
    users_grants.role as role,
    users.email as email,
    users.default_role
from
    users_grants
    right outer join users on users_grants.user = users.user
order by
    users_grants.user