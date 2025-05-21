import base64
from config.loader import ConfigLoader


def verify_credentials(username, password):
    config = ConfigLoader()
    return (username == config.get('auth.username') and 
            password == config.get('auth.password'))
