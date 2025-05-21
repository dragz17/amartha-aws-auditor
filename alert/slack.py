import requests
from scanner.rules import cis_rules

def send_slack_alert(data, webhook_url):
    # Menyiapkan pesan
    message = f"""*HIGH RISK ALERT*\nResource: {data['resource']}\nIssue: {data['issue']}"""
    
    # Menambahkan CIS Rule dan Remediation jika ada
    if data.get('cis_rule') and data.get('remediation'):
        message += f"""\nCIS Rule: {data['cis_rule']}\nRemediation: {data['remediation']}"""
    
    # Kirim ke Slack
    requests.post(webhook_url, json={"text": message})
