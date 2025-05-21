import boto3
from botocore.exceptions import ClientError
from .rules import cis_rules


def scan():
    findings = []
    iam = boto3.client('iam')

    # --- Scan IAM Users ---
    users = iam.list_users()['Users']
    for user in users:
        user_name = user['UserName']

        # Check for MFA
        mfa_devices = iam.list_mfa_devices(UserName=user_name)['MFADevices']
        if not mfa_devices:
            findings.append({
                "resource": user_name,
                "type": "IAM User",
                "risk": (
                    cis_rules["iam_user_without_mfa"]["risk_level"]
                ),
                "issue": "User does not have MFA enabled",
                "cis_rule": (
                    cis_rules["iam_user_without_mfa"]["cis_rule"]
                ),
                "remediation": (
                    cis_rules["iam_user_without_mfa"]["remediation"]
                )
            })

        # Check access keys
        access_keys = iam.list_access_keys(
            UserName=user_name
        )['AccessKeyMetadata']
        for key in access_keys:
            if key['Status'] == 'Active':
                findings.append({
                    "resource": (
                        f"{user_name} - {key['AccessKeyId']}"
                    ),
                    "type": "IAM Access Key",
                    "risk": (
                        cis_rules["iam_root_access_key"]["risk_level"]
                    ),
                    "issue": "Active access key found",
                    "cis_rule": (
                        cis_rules["iam_root_access_key"]["cis_rule"]
                    ),
                    "remediation": (
                        cis_rules["iam_root_access_key"]["remediation"]
                    )
                })

        # Inline policies
        inline_policies = iam.list_user_policies(
            UserName=user_name
        )['PolicyNames']
        for policy_name in inline_policies:
            policy_doc = iam.get_user_policy(
                UserName=user_name,
                PolicyName=policy_name
            )['PolicyDocument']
            statements = policy_doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                if (stmt.get('Effect') == 'Allow' and
                        stmt.get('Action') == '*' and
                        stmt.get('Resource') == '*'):
                    findings.append({
                        "resource": user_name,
                        "type": "IAM User",
                        "risk": (
                            cis_rules["iam_policy_overly_permissive"]
                            ["risk_level"]
                        ),
                        "issue": "Inline policy is overly permissive",
                        "cis_rule": (
                            cis_rules["iam_policy_overly_permissive"]
                            ["cis_rule"]
                        ),
                        "remediation": (
                            cis_rules["iam_policy_overly_permissive"]
                            ["remediation"]
                        )
                    })

        # Attached managed policies
        attached_policies = iam.list_attached_user_policies(
            UserName=user_name
        )['AttachedPolicies']
        for attached_policy in attached_policies:
            policy_arn = attached_policy['PolicyArn']
            policy = iam.get_policy(PolicyArn=policy_arn)
            version_id = policy['Policy']['DefaultVersionId']
            policy_doc = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )['PolicyVersion']['Document']
            statements = policy_doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                if (stmt.get('Effect') == 'Allow' and
                        stmt.get('Action') == '*' and
                        stmt.get('Resource') == '*'):
                    findings.append({
                        "resource": user_name,
                        "type": "IAM User",
                        "risk": (
                            cis_rules["iam_policy_overly_permissive"]
                            ["risk_level"]
                        ),
                        "issue": (
                            f"Attached policy {attached_policy['PolicyName']} "
                            "is overly permissive"
                        ),
                        "cis_rule": (
                            cis_rules["iam_policy_overly_permissive"]
                            ["cis_rule"]
                        ),
                        "remediation": (
                            cis_rules["iam_policy_overly_permissive"]
                            ["remediation"]
                        )
                    })

    # Check password policy
    try:
        password_policy = iam.get_account_password_policy()['PasswordPolicy']
        if not password_policy.get('RequireUppercaseCharacters'):
            findings.append({
                "resource": "IAM Password Policy",
                "type": "IAM Policy",
                "risk": (
                    cis_rules["iam_password_policy"]["risk_level"]
                ),
                "issue": "Password policy does not require uppercase letters",
                "cis_rule": (
                    cis_rules["iam_password_policy"]["cis_rule"]
                ),
                "remediation": (
                    cis_rules["iam_password_policy"]["remediation"]
                )
            })
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            findings.append({
                "resource": "IAM Password Policy",
                "type": "IAM Policy",
                "risk": (
                    cis_rules["iam_password_policy"]["risk_level"]
                ),
                "issue": "No password policy found",
                "cis_rule": (
                    cis_rules["iam_password_policy"]["cis_rule"]
                ),
                "remediation": (
                    cis_rules["iam_password_policy"]["remediation"]
                )
            })
        else:
            print(f"Error checking password policy: {e}")

    return findings
