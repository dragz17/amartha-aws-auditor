import requests
from requests.auth import HTTPBasicAuth
import yaml

# Load config dari YAML
with open('config.yaml') as f:
    config = yaml.safe_load(f)

api_url = f"https://{config['jira']['domain']}.atlassian.net/rest/api/2/issuetype"
auth = HTTPBasicAuth(config['jira']['email'], config['jira']['api_token'])

response = requests.get(api_url, auth=auth)

# Debugging response
print(f"Response Status Code: {response.status_code}")
print(f"Response Text: {response.text}")

if response.status_code == 200:
    issue_types = response.json()
    for issue_type in issue_types:
        print(f"ID: {issue_type['id']}, Name: {issue_type['name']}")
else:
    print(f"Failed to get issue types: {response.status_code} - {response.text}")
