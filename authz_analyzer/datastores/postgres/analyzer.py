"""Analyze authorization for Postgres.

Postgres both users and groups are roles.
Roles can be members of other roles.
In order to bootstrap the database system, a freshly initialized system always contains one predefined role. 
This role is always a “superuser”,
it will have the same name as the operating system user that initialized the database cluster. 
Customarily, this role will be named postgres. 
In order to create more roles you first have to connect as this initial role.

Attributes:
Login:
Only roles that have the LOGIN attribute can be used as the initial role name for a database connection. 
A role with the LOGIN attribute can be considered the same as a “database user”


superuser
A database superuser bypasses all permission checks, except the right to log in. This is a dangerous privilege and should not be used carelessly; it is best to do most of your work as a role that is not a superuser. To create a new database superuser, use CREATE ROLE name SUPERUSER. 
You must do this as a role that is already a superuser.

inheritance of privileges
A role is given permission to inherit the privileges of roles it is a member of, by default. However, to create a role without the permission, use CREATE ROLE name NOINHERIT.

 The database will not let you set up circular membership loops.

member roles that have the INHERIT attribute automatically have use of the privileges of roles of which they are members, including any privileges inherited by those roles. As an example, suppose we have done:

CREATE ROLE joe LOGIN INHERIT;
CREATE ROLE admin NOINHERIT;
CREATE ROLE wheel NOINHERIT;
GRANT admin TO joe;
GRANT wheel TO admin;
Immediately after connecting as role joe, a database session will have use of privileges granted directly to joe plus any privileges granted to admin, because joe “inherits” admin's privileges.

https://www.postgresql.org/docs/15/predefined-roles.html

https://www.postgresql.org/docs/current/sql-grant.html
"""


class PostgresAuthzAnalyzer:
    pass
