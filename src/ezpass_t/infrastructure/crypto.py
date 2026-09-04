from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

class Crypto:
    def derive_secret_key(self, salt: bytes, master_password: str) -> bytes:
        """Derive a 256-bit AES key from the master password and per-user salt."""
        kdf = Scrypt(
            salt=salt,
            length=32,  # 256-bit key
            n=2**14,
            r=8,
            p=1,
        )
        secret_key = kdf.derive(master_password.encode())
        return secret_key

    def encrypt_plaintext(self, secret_key: bytes, nonce: bytes, plaintext: str) -> bytes:
        """Encrypt vault entry plaintext with the session secret key (AES-GCM)."""
        aes = AESGCM(secret_key)
        ciphertext = aes.encrypt(nonce, plaintext.encode(), None)
        return ciphertext
    
    def decrypt_ciphertext(self, secret_key: bytes, nonce: bytes, ciphertext: bytes) -> str:
        """Decrypt a stored vault entry using its nonce and the session secret key."""
        aes = AESGCM(secret_key)
        plaintext = aes.decrypt(nonce, ciphertext, None).decode()
        return plaintext