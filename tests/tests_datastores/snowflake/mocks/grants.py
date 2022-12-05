USER_ONE_ROLE_ONE = [("user_1", "role_1")]
ROLE_ONE_GRANT_TABLE_ONE = [("", "role_1", "SELECT", "db1.schema1.table1", "TABLE")]
NO_ROLES_GRANTS = [("", "", "", "", "")]
ROLE_ONE_TABLE_ONE_THROUGH_ROLE_TWO = [
    ("role_2", "role_1", "USAGE", "", "ROLE"),
    ("", "role_2", "SELECT", "db1.schema1.table1", "TABLE"),
] 
ROLE_TO_ROLE_GRANT_NO_GRANTS = [("role_1", "role_2", "USAGE", "", "ROLE")]
