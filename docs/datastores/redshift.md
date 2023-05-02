Redshift supports [Users](https://docs.aws.amazon.com/redshift/latest/dg/r_Users.html)/[Groups](https://docs.aws.amazon.com/redshift/latest/dg/r_Groups.html) or role-based access control [RBAC](https://docs.aws.amazon.com/redshift/latest/dg/t_Roles.html) model to manage access to data assets.. Roles can be organized hierarchically. All users are assigned to the PUBLIC role by default.

## Setup Access to Scan Amazon Redshift
Use the following commands to create a role with the relevant database privileges, then enter them into the Redshift Credentials input fields.


``` sql
-- create role with privileges;
CREATE ROLE satori_scanner_role;

-- grants the required permissions
GRANT SELECT ON TABLE pg_database,pg_user,pg_group,svv_user_grants,svv_role_grants,svv_relation_privileges TO ROLE satori_scanner_role;

-- create a dedicated user
CREATE USER satori_scanner_user NOCREATEDB NOCREATEUSER SYSLOG ACCESS UNRESTRICTED password 'REPLACE_WITH_A_STRONG_PASSWORD';

-- assign role 'SATORI_SCANNER_ROLE' to the new user
GRANT ROLE satori_scanner_role TO satori_scanner_user;
```

## Scanning Amazon Redshift
```
udps redshift \
    --host <HOST> \
    --username <USERNAME> \
    --password <PASSWORD>
```

## Known Limitations

