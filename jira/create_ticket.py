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


def get_issue_types(config):
    """Get available issue types from Jira project."""
    try:
        api_url = (
            f"https://{config['jira']['domain']}.atlassian.net"
            "/rest/api/2/issuetype"
        )
        auth = HTTPBasicAuth(
            config['jira']['email'],
            config['jira']['api_token']
        )

        response = requests.get(
            api_url,
            auth=auth,
            timeout=10
        )

        if response.status_code == 200:
            issue_types = response.json()
            # Print available issue types for debugging
            print("Available issue types:")
            for it in issue_types:
                print(f"- {it['name']} (ID: {it['id']})")
            return issue_types
        else:
            print(
                f"Failed to get issue types: "
                f"{response.status_code} - {response.text}"
            )
            return None

    except Exception as e:
        print(f"Error getting issue types: {e}")
        return None


def create_jira_ticket(finding, config, issue_type_id):
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
                    "id": issue_type_id
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

        # Get available issue types
        issue_types = get_issue_types(config)
        if not issue_types:
            print("Could not get issue types. Exiting.")
            return

        # Find a suitable issue type (Task or Bug)
        issue_type_id = None
        for it in issue_types:
            if it['name'].lower() in ['task', 'bug', 'issue']:
                issue_type_id = it['id']
                break

        if not issue_type_id:
            print("No suitable issue type found. Using first available type.")
            issue_type_id = issue_types[0]['id']

        # Load findings from the JSON file
        with open('aws-scan-results.json') as f:
            findings = json.load(f)

        # Create tickets for high and medium risk findings
        for finding in findings:
            if finding['risk'] in ['HIGH', 'MEDIUM']:
                ticket_key = create_jira_ticket(finding, config, issue_type_id)
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
