import os
import yaml
from string import Template

class ConfigLoader:
    def __init__(self, config_file='config.yaml'):
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Config file {self.config_file} not found")

        with open(self.config_file, 'r') as f:
            return yaml.safe_load(f)

    def get(self, key_path, default=None):
        """Get config value using dot notation."""
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default

            if value is None:
                return default

        return value

    def set(self, key_path, value):
        """Set config value using dot notation."""
        keys = key_path.split('.')
        config = self.config

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value

    def save(self):
        """Save current config to file."""
        with open(self.config_file, 'w') as f:
            yaml.dump(self.config, f)

    def get_all(self):
        """Get all configuration values."""
        return self.config 