import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_email_alert(findings, config):
    msg = MIMEMultipart()
    msg['From'] = config['sender']
    msg['To'] = config['recipient']
    msg['Subject'] = 'AWS Security Alert'

    body = "Security findings:\n\n"
    for finding in findings:
        body += f"Resource: {finding['resource']}\n"
        body += f"Type: {finding['type']}\n"
        body += f"Risk: {finding['risk']}\n"
        body += f"Issue: {finding['issue']}\n"
        body += f"CIS Rule: {finding['cis_rule']}\n"
        body += f"Remediation: {finding['remediation']}\n\n"

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['username'], config['password'])
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")

