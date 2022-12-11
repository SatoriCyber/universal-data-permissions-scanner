import boto3
from boto3 import Session
from authz_analyzer.utils.aws.pagination import paginate_response_list


def get_iam_users(session: Session) -> Session:
    iam_client = session.client('iam')
    response = iam_client.list_users()

    for user in response["Users"]:
        username = user['UserName']
        user_id = user['UserId']
        arn = user['Arn']
        user_policies = paginate_response_list(iam_client.list_user_policies, 'PolicyNames', UserName=username)
        for user_policy in user_policies:
            policy = iam_client.get_user_policy(UserName=username, PolicyName=user_policy)
            print(f"{username}: user_policy: {policy}")
            
        attached_policies = paginate_response_list(iam_client.list_attached_user_policies, 'AttachedPolicies', UserName=username)
        for attached_policy in attached_policies:
            policy = iam_client.get_policy(PolicyArn=attached_policy['PolicyArn'])["Policy"]    
            print(f"{username}: attached_policy: {policy}")
        