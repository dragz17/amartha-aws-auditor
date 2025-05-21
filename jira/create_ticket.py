import requests
from requests.auth import HTTPBasicAuth
import yaml
import json
import os
from datetime import datetime

def load_config():
    try:
        with open('config.yaml') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return None

def create_jira_ticket(finding, config):
    """Create a Jira ticket for a security finding"""
    try:
        # Prepare the ticket data
        ticket_data = {
            "fields": {
                "project": {
                    "key": config['jira']['project_key']
                },
                "summary": f"AWS Security Finding: {finding['type']} - {finding['issue']}",
                "description": f"""
*Resource:* {finding['resource']}
*Type:* {finding['type']}
*Risk Level:* {finding['risk']}
*Issue:* {finding['issue']}
*CIS Rule:* {finding['cis_rule']}
*Remediation:* {finding['remediation']}
*Found At:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                """,
                "issuetype": {
                    "name": "Bug"  # You might want to adjust this based on your Jira setup
                },
                "priority": {
                    "name": "High" if finding['risk'] == "HIGH" else "Medium"
                }
            }
        }

        # Make the API call to create the ticket
        api_url = f"https://{config['jira']['domain']}.atlassian.net/rest/api/2/issue"
        auth = HTTPBasicAuth(config['jira']['email'], config['jira']['api_token'])
        
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
            print(f"Failed to create Jira ticket: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        print(f"Error creating Jira ticket: {e}")
        return None

def process_findings():
    """Process security findings and create Jira tickets"""
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
                    print(f"Created ticket {ticket_key} for finding: {finding['issue']}")
                else:
                    print(f"Failed to create ticket for finding: {finding['issue']}")

    except Exception as e:
        print(f"Error processing findings: {e}")

if __name__ == "__main__":
    process_findings()
