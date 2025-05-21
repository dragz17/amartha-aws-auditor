import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_email_alert(findings, config):
    msg = MIMEMultipart()
    msg['From'] = config['sender']
    msg['To'] = config['recipient']
    msg['Subject'] = 'AWS Security Compliance Report'

    body = "🚨 AWS Cloud Security Compliance Report\n\n"

    # Group findings by risk level
    high_risk = [f for f in findings if f['risk'] == 'HIGH']
    medium_risk = [f for f in findings if f['risk'] == 'MEDIUM']
    low_risk = [f for f in findings if f['risk'] == 'LOW']

    # Add high risk findings
    if high_risk:
        body += "🔴 HIGH RISK FINDINGS:\n\n"
        for i, finding in enumerate(high_risk, 1):
            body += f"{i}. Resource    : {finding['resource']}\n"
            body += f"   Type       : {finding['type']}\n"
            body += f"   Risk       : {finding['risk']}\n"
            body += f"   Issue      : {finding['issue']}\n"
            body += f"   CIS Rule   : {finding['cis_rule']}\n"
            body += f"   Remediation: {finding['remediation']}\n\n"

    # Add medium risk findings
    if medium_risk:
        body += "🟡 MEDIUM RISK FINDINGS:\n\n"
        for i, finding in enumerate(medium_risk, 1):
            body += f"{i}. Resource    : {finding['resource']}\n"
            body += f"   Type       : {finding['type']}\n"
            body += f"   Risk       : {finding['risk']}\n"
            body += f"   Issue      : {finding['issue']}\n"
            body += f"   CIS Rule   : {finding['cis_rule']}\n"
            body += f"   Remediation: {finding['remediation']}\n\n"

    # Add low risk findings
    if low_risk:
        body += "🟢 LOW RISK FINDINGS:\n\n"
        for i, finding in enumerate(low_risk, 1):
            body += f"{i}. Resource    : {finding['resource']}\n"
            body += f"   Type       : {finding['type']}\n"
            body += f"   Risk       : {finding['risk']}\n"
            body += f"   Issue      : {finding['issue']}\n"
            body += f"   CIS Rule   : {finding['cis_rule']}\n"
            body += f"   Remediation: {finding['remediation']}\n\n"

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['username'], config['password'])
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")
