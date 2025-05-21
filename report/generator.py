import json

def generate_report(findings):
    if not findings:
        return "✅ No misconfigurations found. All checks passed."

    report = "🚨 AWS Cloud Security Compliance Report\n\n"
    for i, finding in enumerate(findings, 1):
        report += f"{i}. Resource    : {finding.get('resource', '-')}\n"
        report += f"   Type       : {finding.get('type', '-')}\n"
        report += f"   Risk       : {finding.get('risk', '-')}\n"
        report += f"   Issue      : {finding.get('issue', '-')}\n"
        report += f"   CIS Rule   : {finding.get('cis_rule', 'N/A')}\n"
        report += f"   Remediation: {finding.get('remediation', 'N/A')}\n"
        report += "\n"

    return report


