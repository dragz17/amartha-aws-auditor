import os
import yaml
from string import Template

class ConfigLoader:
    def __init__(self, config_path='config.yaml'):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self):
        """Load configuration from YAML file or environment variables."""
        # Check if running in GitHub Actions
        if os.getenv('GITHUB_ACTIONS') == 'true':
            return self._load_from_env()
        else:
            return self._load_from_yaml()

    def _load_from_env(self):
        """Load configuration from environment variables (GitHub Actions)."""
        return {
            'auth': {
                'username': os.getenv('AUTH_USERNAME'),
                'password': os.getenv('AUTH_PASSWORD')
            },
            'email': {
                'smtp_server': os.getenv('SMTP_SERVER'),
                'smtp_port': os.getenv('SMTP_PORT'),
                'username': os.getenv('SMTP_USERNAME'),
                'password': os.getenv('SMTP_PASSWORD'),
                'sender': os.getenv('EMAIL_SENDER'),
                'recipient': os.getenv('EMAIL_RECIPIENT')
            },
            'slack': {
                'webhook': os.getenv('SLACK_WEBHOOK')
            },
            'jira': {
                'domain': os.getenv('JIRA_DOMAIN'),
                'email': os.getenv('JIRA_EMAIL'),
                'api_token': os.getenv('JIRA_API_TOKEN'),
                'project_key': os.getenv('JIRA_PROJECT_KEY')
            }
        }

    def _load_from_yaml(self):
        """Load configuration from YAML file (local development)."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)

    def get(self, key, default=None):
        """Get configuration value by key."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
                
        return value if value is not None else default

    def get_all(self):
        """Get all configuration values."""
        return self.config 