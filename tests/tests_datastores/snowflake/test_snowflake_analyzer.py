# from authz_analyzer.datastores.snowflake import SnowflakeAuthzAnalyzer
# from authz_analyzer.datastores.snowflake.model import DBUser, DBRole


# def test_role_of_roles():
#     user_grants = {"Omer": DBUser("Omer", {DBRole("role_1", set(), set())})}
#     results = SnowflakeAuthzAnalyzer._build_authorization_model(user_grants, {}, {})
#     assert user_grants == results
