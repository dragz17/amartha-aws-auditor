cis_rules = {
    # Security Group Rules
    "sg_ssh_open": {
        "cis_rule": (
            "CIS AWS 4.1 – Ensure no security groups allow "
            "unrestricted SSH access"
        ),
        "remediation": (
            "Restrict SSH access to trusted IP addresses only. "
            "Remove 0.0.0.0/0 from port 22."
        ),
        "risk_level": "HIGH"
    },
    "sg_http_open": {
        "cis_rule": (
            "CIS AWS 4.1 – Ensure no security groups allow "
            "unrestricted HTTP access"
        ),
        "remediation": (
            "Restrict HTTP access to trusted IP addresses only. "
            "Remove 0.0.0.0/0 from port 80."
        ),
        "risk_level": "MEDIUM"
    },
    "sg_https_open": {
        "cis_rule": (
            "CIS AWS 4.1 – Ensure no security groups allow "
            "unrestricted HTTPS access"
        ),
        "remediation": (
            "Restrict HTTPS access to trusted IP addresses only. "
            "Remove 0.0.0.0/0 from port 443."
        ),
        "risk_level": "MEDIUM"
    },
    "sg_other_open": {
        "cis_rule": (
            "CIS AWS 4.1 – Ensure no security groups allow "
            "unrestricted access on non-standard ports"
        ),
        "remediation": (
            "Review and restrict access to this port to "
            "trusted IP addresses only."
        ),
        "risk_level": "LOW"
    },
    "sg_rdp_open": {
        "cis_rule": (
            "CIS AWS 4.1 – Ensure no security groups allow "
            "unrestricted RDP access"
        ),
        "remediation": (
            "Restrict RDP access to trusted IP addresses only. "
            "Remove 0.0.0.0/0 from port 3389."
        ),
        "risk_level": "HIGH"
    },

    # IAM Rules
    "iam_policy_overly_permissive": {
        "cis_rule": "CIS AWS 1.5 – Ensure IAM policies are least privileged",
        "remediation": (
            "Ensure IAM policies are scoped to only necessary permissions. "
            "Avoid using 'Action': '*' and 'Resource': '*' in policies."
        ),
        "risk_level": "HIGH"
    },
    "iam_user_without_mfa": {
        "cis_rule": (
            "CIS AWS 1.2 – Ensure multi-factor authentication (MFA) "
            "is enabled for all IAM users"
        ),
        "remediation": (
            "Enable MFA for all IAM users that have a console password."
        ),
        "risk_level": "HIGH"
    },
    "iam_root_access_key": {
        "cis_rule": (
            "CIS AWS 1.4 – Ensure access keys are rotated "
            "every 90 days or less"
        ),
        "remediation": "Rotate access keys every 90 days or less.",
        "risk_level": "HIGH"
    },
    "iam_password_policy": {
        "cis_rule": (
            "CIS AWS 1.7 – Ensure IAM password policy requires "
            "at least one uppercase letter"
        ),
        "remediation": (
            "Update IAM password policy to require uppercase letters, "
            "numbers, and special characters."
        ),
        "risk_level": "MEDIUM"
    },

    # S3 Rules
    "s3_public_access": {
        "cis_rule": (
            "CIS AWS 5.1 – Ensure S3 buckets are not "
            "publicly accessible"
        ),
        "remediation": (
            "Review bucket ACLs and restrict access to trusted accounts only. "
            "Do not grant public read/write permissions."
        ),
        "risk_level": "HIGH"
    },
    "s3_versioning_disabled": {
        "cis_rule": (
            "CIS AWS 5.2 – Ensure S3 bucket versioning is enabled"
        ),
        "remediation": (
            "Enable versioning on S3 buckets to protect against "
            "accidental deletion and maintain object history."
        ),
        "risk_level": "MEDIUM"
    },
    "s3_logging_disabled": {
        "cis_rule": (
            "CIS AWS 5.3 – Ensure S3 bucket access logging is enabled"
        ),
        "remediation": (
            "Enable access logging on S3 buckets to track access requests."
        ),
        "risk_level": "MEDIUM"
    },
    "s3_encryption_disabled": {
        "cis_rule": (
            "CIS AWS 5.4 – Ensure S3 bucket encryption is enabled"
        ),
        "remediation": (
            "Enable server-side encryption for S3 buckets to "
            "protect data at rest."
        ),
        "risk_level": "HIGH"
    },

    # EC2 Rules
    "ec2_public_ip": {
        "cis_rule": (
            "CIS AWS 4.2 – Ensure no EC2 instances have public IPs"
        ),
        "remediation": (
            "Review EC2 instances and remove public IPs if not required. "
            "Use private subnets and NAT gateways instead."
        ),
        "risk_level": "MEDIUM"
    },
    "ec2_unencrypted_volumes": {
        "cis_rule": (
            "CIS AWS 4.3 – Ensure all EC2 volumes are encrypted"
        ),
        "remediation": (
            "Enable encryption for all EC2 volumes to protect data at rest."
        ),
        "risk_level": "HIGH"
    },
    "ec2_public_snapshot": {
        "cis_rule": (
            "CIS AWS 4.4 – Ensure EC2 snapshots are not "
            "publicly accessible"
        ),
        "remediation": (
            "Review and restrict access to EC2 snapshots to "
            "trusted accounts only."
        ),
        "risk_level": "HIGH"
    },
    "ec2_termination_protection": {
        "cis_rule": (
            "CIS AWS 4.5 – Ensure EC2 instances have "
            "termination protection enabled"
        ),
        "remediation": (
            "Enable termination protection for critical EC2 instances "
            "to prevent accidental termination."
        ),
        "risk_level": "MEDIUM"
    }
}
