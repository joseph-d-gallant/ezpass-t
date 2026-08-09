from dataclasses import dataclass

@dataclass
class User:
    id: int
    username: str
    email: str
    salt: bytes
    hash: str

@dataclass
class Password:
    id: int
    user_id: int
    name: str
    nonce: bytes
    ciphertext: bytes