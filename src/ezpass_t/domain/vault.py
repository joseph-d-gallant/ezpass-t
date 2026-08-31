from dataclasses import dataclass, field
from .password import Password

@dataclass
class Vault:
    """In-memory index of decrypted password metadata keyed by password id."""

    passwords: dict[int, Password] = field(default_factory=dict)
    
    def add(self, password: Password):
        """Insert or replace a password entry in the vault cache."""
        self.passwords[password.id] = password