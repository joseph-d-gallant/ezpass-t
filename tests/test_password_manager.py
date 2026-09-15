"""Critical security tests for authentication, session handling, and vault CRUD."""

import string
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from argon2 import PasswordHasher

from ezpass_t.domain.models import Password, Session, User, Vault
from ezpass_t.services.exceptions import (
    AuthenticationError,
    EmptyVaultError,
    PasswordNotCachedError,
    SessionIsExpiredError,
)
from ezpass_t.services.password_manager import PasswordManager

MASTER_PASSWORD = "CorrectHorse1"


# Fixtures inject mocks as arguments into test parameters at runtime
@pytest.fixture
def user_repo():
    return Mock()


@pytest.fixture
def password_repo():
    return Mock()


@pytest.fixture
def crypto():
    mock_crypto = Mock()
    # Set return values of mocked crypto methods
    mock_crypto.derive_secret_key.return_value = b"k" * 32
    mock_crypto.encrypt_plaintext.return_value = b"ciphertext"
    mock_crypto.decrypt_ciphertext.return_value = "decrypted-secret"
    return mock_crypto


@pytest.fixture
def password_manager(user_repo, password_repo, crypto) -> PasswordManager:
    return PasswordManager(user_repo, password_repo, crypto)


def _user(password: str = MASTER_PASSWORD) -> User:
    return User(
        id=1,
        username="alice",
        email="alice@example.com",
        salt=b"salt" * 4,
        hash=PasswordHasher().hash(password),
    )


def _login_fields(username: str = "alice", password: str = MASTER_PASSWORD):
    return SimpleNamespace(
        username_field=SimpleNamespace(value=username),
        password_field=SimpleNamespace(value=password),
    )


def _authenticated_session(user: User | None = None) -> Session:
    session = Mock(spec=Session)
    session.user = user or _user()
    session.secret_key = b"k" * 32
    session.vault = Vault()
    session.is_authenticated.return_value = True
    return session


def test_generate_password_includes_required_character_classes(
    password_manager: PasswordManager,
):
    special = "?!#@$"
    generated = password_manager._generate_password(16, special)

    assert len(generated) == 16
    assert any(char.islower() for char in generated)
    assert any(char.isupper() for char in generated)
    assert any(char.isdigit() for char in generated)
    assert any(char in special for char in generated)
    assert all(
        char in string.ascii_letters + string.digits + special for char in generated
    )


def test_login_opens_session_and_derives_key_from_master_password(
    password_manager: PasswordManager, user_repo, crypto
):
    user = _user()
    user_repo.get_by_username.return_value = user
    user_repo.get_all_by_user_id = Mock()
    password_manager.password_repo.get_all_by_user_id.return_value = []

    result = password_manager.login(_login_fields())

    assert result is True
    assert password_manager.session is not None
    assert password_manager.session.user.id == user.id
    assert password_manager.is_authenticated() is True
    # Assert the mocked method was only called once, and it used specific arguments
    crypto.derive_secret_key.assert_called_once_with(user.salt, MASTER_PASSWORD)


def test_login_rejects_wrong_master_password(
    password_manager: PasswordManager, user_repo
):
    user_repo.get_by_username.return_value = _user()

    with pytest.raises(AuthenticationError):
        password_manager.login(_login_fields(password="WrongPassword1"))

    assert password_manager.session is None
    assert password_manager.is_authenticated() is False


def test_create_user_persists_argon2_hash_and_random_salt_not_plaintext(
    password_manager: PasswordManager, user_repo
):
    fields = SimpleNamespace(
        username_field=SimpleNamespace(value="new_user_1"),
        email_field=SimpleNamespace(value="new@example.com"),
        password_field=SimpleNamespace(value=MASTER_PASSWORD),
    )

    password_manager.create_user(fields)

    # Set created_user to the first arg passed into user_repo.create
    created_user = user_repo.create.call_args.args[0]
    assert created_user.username == "new_user_1"
    assert created_user.hash != MASTER_PASSWORD
    assert created_user.hash.startswith("$argon2")
    assert MASTER_PASSWORD.encode() not in created_user.hash.encode()
    assert isinstance(created_user.salt, bytes)
    assert len(created_user.salt) == 16
    PasswordHasher().verify(created_user.hash, MASTER_PASSWORD)


def test_vault_read_requires_live_session_and_nonempty_vault(
    password_manager: PasswordManager,
):
    password_manager.session = None
    assert password_manager.is_authenticated() is False

    session = _authenticated_session()
    session.is_authenticated.return_value = False
    password_manager.session = session
    with pytest.raises(SessionIsExpiredError):
        password_manager.get_passwords()

    session.is_authenticated.return_value = True
    with pytest.raises(EmptyVaultError):
        password_manager.get_passwords()


def test_create_password_encrypts_before_persist_and_skips_empty_names(
    password_manager: PasswordManager, password_repo, crypto
):
    session = _authenticated_session()
    password_manager.session = session
    stored = Password(7, session.user.id, "github", b"n" * 12, b"ciphertext")
    password_repo.create.return_value = stored

    password_manager.create_password("")
    # Fail if the methods were called
    password_repo.create.assert_not_called()
    crypto.encrypt_plaintext.assert_not_called()

    password_manager.create_password("github", 16, "?!#@$")

    crypto.encrypt_plaintext.assert_called_once()
    # Unpack args passed into crypto.encrypt_plaintext
    secret_key, _nonce, plaintext = crypto.encrypt_plaintext.call_args.args
    assert secret_key == session.secret_key
    assert plaintext != "github"
    persisted = password_repo.create.call_args.args[0]
    assert persisted.ciphertext == b"ciphertext"
    assert persisted.ciphertext != plaintext.encode()
    assert persisted.name == "github"
    assert session.vault.get_password(7) is stored


def test_logout_and_missing_entries_do_not_leak_vault_state(
    password_manager: PasswordManager, user_repo, password_repo
):
    session = _authenticated_session()
    password_manager.session = session
    password_manager.logout()
    assert password_manager.session is None
    assert password_manager.is_authenticated() is False

    password_manager.session = _authenticated_session()
    with pytest.raises(PasswordNotCachedError):
        password_manager.get_one_password(999)

    session_user = password_manager.session.user
    password_manager.delete_user()
    user_repo.delete_by_id.assert_called_once_with(session_user)
    assert password_manager.session is None
    password_repo.delete.assert_not_called()
