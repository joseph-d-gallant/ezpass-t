import time
from dataclasses import dataclass, field

from ..config import SESSION_TIMEOUT

# --- Persistence and session models ---


@dataclass
class User:
    """Application user with Argon2 hash and per-user encryption salt."""

    id: int | None
    username: str
    email: str
    salt: bytes
    hash: str


@dataclass
class Password:
    """Encrypted vault entry stored for a user."""

    id: int
    user_id: int
    name: str
    nonce: bytes
    ciphertext: bytes
    created_at: int = field(default_factory=lambda: int(time.time()))


@dataclass
class Vault:
    """In-memory index of decrypted password metadata keyed by password id."""

    passwords: dict[int, Password] = field(default_factory=dict)

    def add_password(self, password: Password) -> None:
        """Insert or replace a password entry in the vault cache."""
        self.passwords[password.id] = password

    def delete_password(self, password_id: int) -> None:
        del self.passwords[password_id]

    def update_password(
        self, password_id: int, nonce: bytes, ciphertext: bytes
    ) -> None:
        self.passwords[password_id].nonce = nonce
        self.passwords[password_id].ciphertext = ciphertext

    def get_password(self, password_id: int) -> Password:
        return self.passwords[password_id]


@dataclass
class Session:
    """Authenticated runtime state, including derived encryption key and vault."""

    user: User
    secret_key: bytes
    vault: Vault
    last_active: float
    authenticated: bool

    def is_authenticated(self):
        if not self.authenticated:
            return False
        # add session timeout constant
        return time.monotonic() - self.last_active < SESSION_TIMEOUT
