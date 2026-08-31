import time
from dataclasses import dataclass, field

@dataclass
class Password:
    """Encrypted vault entry stored for a user."""

    id: int
    user_id: int
    name: str
    nonce: bytes
    ciphertext: bytes
    created_at: int = field(default_factory=lambda: int(time.time()))
    

    @classmethod
    def from_row(cls, row):
        """Construct a Password from a sqlite3.Row."""
        return cls(**dict(row))
    
    @classmethod
    def from_rows(cls, rows):
        """Construct a list of Password objects from query results."""
        passwords = []
        for row in rows:
            passwords.append(cls.from_row(row))
        return passwords