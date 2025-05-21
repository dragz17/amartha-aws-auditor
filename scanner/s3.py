import boto3
from botocore.exceptions import ClientError
from .rules import cis_rules


def scan():
    findings = []
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        bucket_name = bucket['Name']

        # Check public access
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if (grantee.get('URI') ==
                        'http://acs.amazonaws.com/groups/global/AllUsers'):
                    findings.append({
                        "resource": bucket_name,
                        "type": "S3 Bucket",
                        "risk": (
                            cis_rules["s3_public_access"]["risk_level"]
                        ),
                        "issue": "Bucket is publicly accessible",
                        "cis_rule": (
                            cis_rules["s3_public_access"]["cis_rule"]
                        ),
                        "remediation": (
                            cis_rules["s3_public_access"]["remediation"]
                        )
                    })
        except Exception as e:
            print(f"Error checking ACL for {bucket_name}: {e}")

        # Check versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                findings.append({
                    "resource": bucket_name,
                    "type": "S3 Bucket",
                    "risk": (
                        cis_rules["s3_versioning_disabled"]["risk_level"]
                    ),
                    "issue": "Bucket versioning is not enabled",
                    "cis_rule": (
                        cis_rules["s3_versioning_disabled"]["cis_rule"]
                    ),
                    "remediation": (
                        cis_rules["s3_versioning_disabled"]["remediation"]
                    )
                })
        except Exception as e:
            print(f"Error checking versioning for {bucket_name}: {e}")

        # Check logging
        try:
            logging = s3.get_bucket_logging(Bucket=bucket_name)
            if not logging.get('LoggingEnabled'):
                findings.append({
                    "resource": bucket_name,
                    "type": "S3 Bucket",
                    "risk": (
                        cis_rules["s3_logging_disabled"]["risk_level"]
                    ),
                    "issue": "Bucket access logging is not enabled",
                    "cis_rule": (
                        cis_rules["s3_logging_disabled"]["cis_rule"]
                    ),
                    "remediation": (
                        cis_rules["s3_logging_disabled"]["remediation"]
                    )
                })
        except Exception as e:
            print(f"Error checking logging for {bucket_name}: {e}")

        # Check encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            if not encryption.get('ServerSideEncryptionConfiguration'):
                findings.append({
                    "resource": bucket_name,
                    "type": "S3 Bucket",
                    "risk": (
                        cis_rules["s3_encryption_disabled"]["risk_level"]
                    ),
                    "issue": "Bucket encryption is not enabled",
                    "cis_rule": (
                        cis_rules["s3_encryption_disabled"]["cis_rule"]
                    ),
                    "remediation": (
                        cis_rules["s3_encryption_disabled"]["remediation"]
                    )
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                findings.append({
                    "resource": bucket_name,
                    "type": "S3 Bucket",
                    "risk": (
                        cis_rules["s3_encryption_disabled"]["risk_level"]
                    ),
                    "issue": "Bucket encryption is not enabled",
                    "cis_rule": (
                        cis_rules["s3_encryption_disabled"]["cis_rule"]
                    ),
                    "remediation": (
                        cis_rules["s3_encryption_disabled"]["remediation"]
                    )
                })
            else:
                print(f"Error checking encryption for {bucket_name}: {e}")

    return findings
