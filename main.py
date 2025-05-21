from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from scanner import s3, iam, ec2, sg
from report.generator import generate_report
from auth.basic import verify_credentials
from alert.email import send_email_alert
from alert.slack import send_slack_alert
from config.loader import ConfigLoader

app = FastAPI()
security = HTTPBasic()
config = ConfigLoader()


def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    if not verify_credentials(credentials.username, credentials.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return credentials.username


@app.get("/scan/s3")
def scan_s3(user: str = Depends(get_current_user)):
    results = s3.scan()
    send_alerts(results)
    return results


@app.get("/scan/iam")
def scan_iam(user: str = Depends(get_current_user)):
    results = iam.scan()
    send_alerts(results)
    return results


@app.get("/scan/ec2")
def scan_ec2(user: str = Depends(get_current_user)):
    results = ec2.scan()
    send_alerts(results)
    return results


@app.get("/scan/security-groups")
def scan_sg(user: str = Depends(get_current_user)):
    results = sg.scan()
    send_alerts(results)
    return results


@app.get("/report")
def report(user: str = Depends(get_current_user)):
    return generate_report()


def send_alerts(results):
    # Group findings by risk level
    high_risk_findings = [r for r in results if r["risk"] == "HIGH"]
    medium_risk_findings = [r for r in results if r["risk"] == "MEDIUM"]
    low_risk_findings = [r for r in results if r["risk"] == "LOW"]

    # Send alerts for high risk findings
    if high_risk_findings:
        send_email_alert(high_risk_findings, config.get('email'))
        for r in high_risk_findings:
            send_slack_alert(r, config.get('slack.webhook'))

    # Send alerts for medium risk findings
    if medium_risk_findings:
        send_email_alert(medium_risk_findings, config.get('email'))
        for r in medium_risk_findings:
            send_slack_alert(r, config.get('slack.webhook'))

    # Only send email for low risk findings (no Slack alerts)
    if low_risk_findings:
        send_email_alert(low_risk_findings, config.get('email'))

