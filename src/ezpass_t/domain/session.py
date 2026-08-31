from dataclasses import dataclass
from .user import User
from .vault import Vault

@dataclass
class Session:
    """Authenticated runtime state, including derived encryption key and vault."""
    user: User
    secret_key: bytes
    vault: Vault
    last_active: float
    authenticated: bool