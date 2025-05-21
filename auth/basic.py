from config.loader import ConfigLoader

config = ConfigLoader()

def verify_credentials(username: str, password: str) -> bool:
    """Verify basic auth credentials against config."""
    return (
        username == config.get('auth.username') and
        password == config.get('auth.password')
    )
