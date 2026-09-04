from ezpass_t.services.password_manager import PasswordManager
from unittest.mock import Mock
from src.ezpass_t.models import Session
import os

def test_encrypt_and_decrypt_returns_original():
    user_repo = password_repo = Mock()
    
    password_manager = PasswordManager(user_repo, password_repo)
    secret_key = password_manager.derive_secret_key(b"salt", "master_password")
    
    session = Mock()
    session.secret_key = secret_key
    password_manager.session = session
    
    nonce = os.urandom(12)
    original_plaintext = "rawdata"
    ciphertext = password_manager.encrypt_plaintext(nonce, original_plaintext)
    plaintext = password_manager.decrypt_ciphertext(nonce, ciphertext)
    
    assert plaintext == original_plaintext

def test_secret_key_reproducibility():
    user_repo = password_repo = Mock()
    password_manager = PasswordManager(user_repo, password_repo)
    original_secret_key = password_manager.derive_secret_key(b"salt", "master_password")
    secret_key = password_manager.derive_secret_key(b"salt", "master_password")
    assert secret_key == original_secret_key
