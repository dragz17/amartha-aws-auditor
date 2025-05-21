import requests


def send_slack_alert(finding, webhook_url):
    if not webhook_url:
        print("Error: Slack webhook URL is empty")
        return

    message = {
        "text": (
            f"🚨 *AWS Security Alert*\n"
            f"*Resource:* {finding['resource']}\n"
            f"*Type:* {finding['type']}\n"
            f"*Risk:* {finding['risk']}\n"
            f"*Issue:* {finding['issue']}\n"
            f"*CIS Rule:* {finding['cis_rule']}\n"
            f"*Remediation:* {finding['remediation']}"
        )
    }

    try:
        print(f"Sending Slack alert to webhook: {webhook_url[:20]}...")
        response = requests.post(
            webhook_url,
            json=message,
            timeout=10  # Adding 10 second timeout
        )
        response.raise_for_status()
        print("Slack alert sent successfully")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send Slack alert: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response text: {e.response.text}")
    except Exception as e:
        print(f"Unexpected error sending Slack alert: {str(e)}")
