"""Critical security tests for AES-GCM encryption and Scrypt key derivation."""

import os

import pytest
from cryptography.exceptions import InvalidTag

from ezpass_t.infrastructure.crypto import Crypto


@pytest.fixture
def crypto() -> Crypto:
    return Crypto()


@pytest.fixture
def secret_key(crypto: Crypto) -> bytes:
    return crypto.derive_secret_key(b"per-user-salt-16", "master_password")


def test_encrypt_and_decrypt_returns_original(crypto: Crypto, secret_key: bytes):
    nonce = os.urandom(12)
    original_plaintext = "rawdata"

    ciphertext = crypto.encrypt_plaintext(secret_key, nonce, original_plaintext)
    plaintext = crypto.decrypt_ciphertext(secret_key, nonce, ciphertext)

    assert plaintext == original_plaintext


def test_secret_key_reproducibility(crypto: Crypto):
    salt = b"per-user-salt-16"
    original_secret_key = crypto.derive_secret_key(salt, "master_password")
    secret_key = crypto.derive_secret_key(salt, "master_password")

    assert secret_key == original_secret_key
    assert len(secret_key) == 32


def test_different_salt_or_password_yields_different_keys(crypto: Crypto):
    salt = b"per-user-salt-16"
    key = crypto.derive_secret_key(salt, "master_password")

    assert key != crypto.derive_secret_key(b"other-user-salt!", "master_password")
    assert key != crypto.derive_secret_key(salt, "wrong_master_password")


def test_ciphertext_is_not_plaintext(crypto: Crypto, secret_key: bytes):
    nonce = os.urandom(12)
    plaintext = "super-secret-vault-entry"
    ciphertext = crypto.encrypt_plaintext(secret_key, nonce, plaintext)

    assert plaintext.encode() not in ciphertext
    assert ciphertext != plaintext.encode()
    assert len(ciphertext) > len(plaintext.encode())


def test_decrypt_rejects_wrong_key(crypto: Crypto, secret_key: bytes):
    nonce = os.urandom(12)
    ciphertext = crypto.encrypt_plaintext(secret_key, nonce, "vault-secret")
    attacker_key = crypto.derive_secret_key(b"per-user-salt-16", "guessed_password")

    with pytest.raises(InvalidTag):
        crypto.decrypt_ciphertext(attacker_key, nonce, ciphertext)


def test_decrypt_rejects_wrong_nonce_or_tampered_ciphertext(
    crypto: Crypto, secret_key: bytes
):
    nonce = os.urandom(12)
    ciphertext = crypto.encrypt_plaintext(secret_key, nonce, "vault-secret")
    tampered = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]

    with pytest.raises(InvalidTag):
        crypto.decrypt_ciphertext(secret_key, os.urandom(12), ciphertext)
    with pytest.raises(InvalidTag):
        crypto.decrypt_ciphertext(secret_key, nonce, tampered)


def test_roundtrip_supports_unicode_and_empty_secrets(
    crypto: Crypto, secret_key: bytes
):
    for plaintext in ("", "пароль🔒", "line1\nline2\twith\x00null"):
        nonce = os.urandom(12)
        ciphertext = crypto.encrypt_plaintext(secret_key, nonce, plaintext)
        assert crypto.decrypt_ciphertext(secret_key, nonce, ciphertext) == plaintext
