from dataclasses import dataclass, field
import time

@dataclass
class UserRecord:
    id: int | None
    username: str
    email: str
    salt: bytes
    hash: str


@dataclass
class PasswordRecord:
    id: int
    user_id: int
    name: str
    nonce: bytes
    ciphertext: bytes
    created_at: int = field(default_factory=lambda: int(time.time()))