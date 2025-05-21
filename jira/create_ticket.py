import requests
from requests.auth import HTTPBasicAuth
import yaml
import json
from datetime import datetime


def load_config():
    """Load configuration from YAML file."""
    try:
        with open('config.yaml') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return None


def create_jira_ticket(finding, config):
    """Create a Jira ticket for a security finding."""
    try:
        # Prepare the ticket data
        ticket_data = {
            "fields": {
                "project": {
                    "key": config['jira']['project_key']
                },
                "summary": (
                    f"AWS Security Finding: {finding['type']} - "
                    f"{finding['issue']}"
                ),
                "description": (
                    f"*Resource:* {finding['resource']}\n"
                    f"*Type:* {finding['type']}\n"
                    f"*Risk Level:* {finding['risk']}\n"
                    f"*Issue:* {finding['issue']}\n"
                    f"*CIS Rule:* {finding['cis_rule']}\n"
                    f"*Remediation:* {finding['remediation']}\n"
                    f"*Found At:* "
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                ),
                "issuetype": {
                    "name": "Bug"  # Adjust based on your Jira setup
                },
                "priority": {
                    "name": "High" if finding['risk'] == "HIGH" else "Medium"
                }
            }
        }

        # Make the API call to create the ticket
        api_url = (
            f"https://{config['jira']['domain']}.atlassian.net"
            "/rest/api/2/issue"
        )
        auth = HTTPBasicAuth(
            config['jira']['email'],
            config['jira']['api_token']
        )
        
        response = requests.post(
            api_url,
            json=ticket_data,
            auth=auth,
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        if response.status_code == 201:
            ticket = response.json()
            print(f"Successfully created Jira ticket: {ticket['key']}")
            return ticket['key']
        else:
            print(
                f"Failed to create Jira ticket: "
                f"{response.status_code} - {response.text}"
            )
            return None

    except Exception as e:
        print(f"Error creating Jira ticket: {e}")
        return None


def process_findings():
    """Process security findings and create Jira tickets."""
    try:
        # Load config
        config = load_config()
        if not config:
            return

        # Load findings from the JSON file
        with open('aws-scan-results.json') as f:
            findings = json.load(f)

        # Create tickets for high and medium risk findings
        for finding in findings:
            if finding['risk'] in ['HIGH', 'MEDIUM']:
                ticket_key = create_jira_ticket(finding, config)
                if ticket_key:
                    print(
                        f"Created ticket {ticket_key} for finding: "
                        f"{finding['issue']}"
                    )
                else:
                    print(
                        f"Failed to create ticket for finding: "
                        f"{finding['issue']}"
                    )

    except Exception as e:
        print(f"Error processing findings: {e}")


if __name__ == "__main__":
    process_findings()
