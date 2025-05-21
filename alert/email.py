import smtplib
from email.mime.text import MIMEText
from report.generator import generate_report

def send_email_alert(findings, email_config):
    try:
        report_body = generate_report(findings)
        msg = MIMEText(report_body)
        msg['Subject'] = 'AWS Security Compliance Report'
        msg['From'] = email_config['sender']
        msg['To'] = email_config['recipient']

        with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            server.send_message(msg)
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")
        raise  # biar FastAPI juga return 500 + error message

