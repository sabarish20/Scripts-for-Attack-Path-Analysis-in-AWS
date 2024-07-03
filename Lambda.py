import boto3
import argparse
import json

def check_perms(access_key_id, secret_access_key, region, session_token=None):

    sts_kwargs = {
        'aws_access_key_id': access_key_id,
        'aws_secret_access_key': secret_access_key,
        'region_name': region
    }
    if session_token:
        sts_kwargs['aws_session_token'] = session_token
    sts = boto3.client('sts', **sts_kwargs)

 
    try:
        response = sts.get_caller_identity()
    except sts.exceptions.ClientError as e:
        print(f"Error: {e.response['Error']['Message']}")
        return

    caller_arn = response['Arn']
    principal_type = caller_arn.split(":")[5].split("/")[-2]  
    principal_name = caller_arn.split("/")[-1] 


    iam = boto3.client('iam', **sts_kwargs)
    attached_policies = []
    inline_policies = []

    if principal_type == 'user':
        attached_policies = iam.list_attached_user_policies(UserName=principal_name)
        inline_policies = iam.list_user_policies(UserName=principal_name)
    elif principal_type == 'role':
        attached_policies = iam.list_attached_role_policies(RoleName=principal_name)
        inline_policies = iam.list_role_policies(RoleName=principal_name)

 
    required_permissions = [
        'iam:PassRole',
        'lambda:CreateFunction',
        'lambda:InvokeFunction',
        'lambda:AddPermission'
    ]


    def check_policy_document(policy_document, required_permissions):
        if isinstance(policy_document, str):
            policy_document = json.loads(policy_document)
        matched_permissions = []
        for statement in policy_document.get('Statement', []):
            if isinstance(statement, dict) and statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                matched_permissions.extend([action for action in actions if action in required_permissions])
        return matched_permissions


    found_permissions = set()
    for policy in attached_policies.get('AttachedPolicies', []):
        policy_arn = policy['PolicyArn']
        policy_name = policy['PolicyName']
        policy_versions = iam.list_policy_versions(PolicyArn=policy_arn)
        for version in policy_versions['Versions']:
            version_id = version['VersionId']
            try:
                policy_version_details = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                policy_document = policy_version_details['PolicyVersion']['Document']
                matched_permissions = check_policy_document(policy_document, required_permissions)
                if matched_permissions:
                    found_permissions.update(matched_permissions)
            except iam.exceptions.NoSuchEntityException:
                continue


    for policy_name in inline_policies.get('PolicyNames', []):
        try:
            if principal_type == 'user':
                policy_document = iam.get_user_policy(UserName=principal_name, PolicyName=policy_name)['PolicyDocument']
            elif principal_type == 'role':
                policy_document = iam.get_role_policy(RoleName=principal_name, PolicyName=policy_name)['PolicyDocument']
            matched_permissions = check_policy_document(policy_document, required_permissions)
            if matched_permissions:
                found_permissions.update(matched_permissions)
        except iam.exceptions.NoSuchEntityException:
            continue

    if found_permissions:
        print(f"{principal_type} {principal_name} has the following permissions which can lead to potential attack pathways:")
        for permission in found_permissions:
            print(f" - {permission}")
    else:
        print(f"{principal_type} {principal_name} does not have any of the specified permissions.")

if __name__ == '__main__':
 
    parser = argparse.ArgumentParser(description='Check IAM and Lambda permissions for the caller')
    parser.add_argument('--access-key-id', required=True)
    parser.add_argument('--secret-access-key', required=True)
    parser.add_argument('--region', required=True)
    parser.add_argument('--session-token', help='AWS session token (optional)', default=None)
    args = parser.parse_args()

    check_perms(args.access_key_id, args.secret_access_key, args.region, args.session_token)
