from dataclasses import dataclass

@dataclass
class User:
    """Application user with Argon2 hash and per-user encryption salt."""

    id: int | None
    username: str
    email: str
    salt: bytes
    hash: str
    
    @classmethod
    def from_row(cls, row):
        """Construct a User from a sqlite3.Row or mapping."""
        return cls(**dict(row))