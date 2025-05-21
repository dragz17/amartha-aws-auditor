import boto3
from .rules import cis_rules


def scan():
    findings = []
    ec2 = boto3.client('ec2')
    security_groups = ec2.describe_security_groups()['SecurityGroups']

    for sg in security_groups:
        for permission in sg['IpPermissions']:
            for ip_range in permission.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    port = permission.get('FromPort', 'ALL')
                    finding = {
                        "resource": sg['GroupId'],
                        "type": "Security Group",
                        "risk": "HIGH",
                        "issue": f"Open to the world on port {port}"
                    }

                    # Masukkan info CIS untuk port 22 (SSH)
                    if port == 22:
                        finding.update({
                            "risk": (
                                cis_rules["sg_ssh_open"]["risk_level"]
                            ),
                            "cis_rule": (
                                cis_rules["sg_ssh_open"]["cis_rule"]
                            ),
                            "remediation": (
                                cis_rules["sg_ssh_open"]["remediation"]
                            )
                        })
                    # Masukkan info CIS untuk port 80 (HTTP)
                    elif port == 80:
                        finding.update({
                            "risk": (
                                cis_rules["sg_http_open"]["risk_level"]
                            ),
                            "cis_rule": (
                                cis_rules["sg_http_open"]["cis_rule"]
                            ),
                            "remediation": (
                                cis_rules["sg_http_open"]["remediation"]
                            )
                        })
                    # Masukkan info CIS untuk port 443 (HTTPS)
                    elif port == 443:
                        finding.update({
                            "risk": (
                                cis_rules["sg_https_open"]["risk_level"]
                            ),
                            "cis_rule": (
                                cis_rules["sg_https_open"]["cis_rule"]
                            ),
                            "remediation": (
                                cis_rules["sg_https_open"]["remediation"]
                            )
                        })
                    # Masukkan info CIS untuk port 3389 (RDP)
                    elif port == 3389:
                        finding.update({
                            "risk": (
                                cis_rules["sg_rdp_open"]["risk_level"]
                            ),
                            "cis_rule": (
                                cis_rules["sg_rdp_open"]["cis_rule"]
                            ),
                            "remediation": (
                                cis_rules["sg_rdp_open"]["remediation"]
                            )
                        })
                    # Masukkan info CIS untuk port lainnya
                    else:
                        finding.update({
                            "risk": (
                                cis_rules["sg_other_open"]["risk_level"]
                            ),
                            "cis_rule": (
                                cis_rules["sg_other_open"]["cis_rule"]
                            ),
                            "remediation": (
                                cis_rules["sg_other_open"]["remediation"]
                            )
                        })
                    findings.append(finding)
    return findings
