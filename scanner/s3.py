import boto3
from .rules import cis_rules

def scan():
    findings = []
    s3 = boto3.client('s3')
    response = s3.list_buckets()

    for bucket in response['Buckets']:
        name = bucket['Name']
        
        # Check public access
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                if 'AllUsers' in grant['Grantee'].get('URI', ''):
                    findings.append({
                        "resource": name,
                        "type": "S3 Bucket",
                        "risk": cis_rules["s3_public_access"]["risk_level"],
                        "issue": "Bucket is publicly accessible",
                        "cis_rule": cis_rules["s3_public_access"]["cis_rule"],
                        "remediation": cis_rules["s3_public_access"]["remediation"]
                    })
        except Exception as e:
            print(f"Error checking bucket ACL for {name}: {e}")

        # Check versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get('Status') != 'Enabled':
                findings.append({
                    "resource": name,
                    "type": "S3 Bucket",
                    "risk": cis_rules["s3_versioning_disabled"]["risk_level"],
                    "issue": "Bucket versioning is not enabled",
                    "cis_rule": cis_rules["s3_versioning_disabled"]["cis_rule"],
                    "remediation": cis_rules["s3_versioning_disabled"]["remediation"]
                })
        except Exception as e:
            print(f"Error checking versioning for {name}: {e}")

        # Check logging
        try:
            logging = s3.get_bucket_logging(Bucket=name)
            if not logging.get('LoggingEnabled'):
                findings.append({
                    "resource": name,
                    "type": "S3 Bucket",
                    "risk": cis_rules["s3_logging_disabled"]["risk_level"],
                    "issue": "Bucket access logging is not enabled",
                    "cis_rule": cis_rules["s3_logging_disabled"]["cis_rule"],
                    "remediation": cis_rules["s3_logging_disabled"]["remediation"]
                })
        except Exception as e:
            print(f"Error checking logging for {name}: {e}")

        # Check encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=name)
            if not encryption.get('ServerSideEncryptionConfiguration'):
                findings.append({
                    "resource": name,
                    "type": "S3 Bucket",
                    "risk": cis_rules["s3_encryption_disabled"]["risk_level"],
                    "issue": "Bucket encryption is not enabled",
                    "cis_rule": cis_rules["s3_encryption_disabled"]["cis_rule"],
                    "remediation": cis_rules["s3_encryption_disabled"]["remediation"]
                })
        except Exception as e:
            print(f"Error checking encryption for {name}: {e}")

    return findings
