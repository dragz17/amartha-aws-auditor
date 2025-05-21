import requests


def send_slack_alert(finding, webhook_url):
    message = {
        "text": f"*AWS Security Alert*\n"
                f"Resource: {finding['resource']}\n"
                f"Type: {finding['type']}\n"
                f"Risk: {finding['risk']}\n"
                f"Issue: {finding['issue']}\n"
                f"CIS Rule: {finding['cis_rule']}\n"
                f"Remediation: {finding['remediation']}"
    }

    try:
        response = requests.post(webhook_url, json=message)
        response.raise_for_status()
    except Exception as e:
        print(f"Failed to send Slack alert: {e}")
