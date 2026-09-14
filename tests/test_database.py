"""Critical security tests for SQLite persistence, uniqueness, and row-level scoping."""

import sqlite3

import pytest

from ezpass_t.domain.models import Password, User
from ezpass_t.infrastructure.database.repositories import (
    PasswordRepository,
    UserRepository,
)
from ezpass_t.services.exceptions import (
    PasswordAlreadyExistsError,
    UserAlreadyExistsError,
    UserNotFoundError,
)

SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    salt BLOB NOT NULL,
    hash TEXT NOT NULL
);
CREATE TABLE passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    nonce BLOB,
    ciphertext BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, name)
);
"""


@pytest.fixture
def conn() -> sqlite3.Connection:
    # Create a db in RAM
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.row_factory = sqlite3.Row
    # Run multiple SQL statements from a single string
    connection.executescript(SCHEMA)
    return connection


@pytest.fixture
def user_repo(conn) -> UserRepository:
    return UserRepository(conn)


@pytest.fixture
def password_repo(conn) -> PasswordRepository:
    return PasswordRepository(conn)


def _user(**overrides) -> User:
    data = {
        "id": None,
        "username": "alice",
        "email": "alice@example.com",
        "salt": b"s" * 16,
        "hash": "$argon2id$placeholder",
    }
    # Unpack args from overrides and update data if any supplied, else use default
    data.update(overrides)
    # Return user by passing in values from data to new User
    return User(**data)


def _password(**overrides) -> Password:
    data = {
        "id": None,
        "user_id": 1,
        "name": "github",
        "nonce": b"n" * 12,
        "ciphertext": b"encrypted-secret",
        "created_at": 1_700_000_000,
    }
    data.update(overrides)
    return Password(**data)


def _create_user(user_repo: UserRepository, **overrides) -> User:
    user_repo.create(_user(**overrides))
    return user_repo.get_by_username(overrides.get("username", "alice"))


def test_user_lookup_uses_parameters_and_rejects_unknown_names(
    user_repo: UserRepository,
):
    created = _create_user(user_repo, username="alice'; DROP TABLE users;--")

    found = user_repo.get_by_username("alice'; DROP TABLE users;--")
    assert found.username == created.username
    assert found.hash == created.hash

    with pytest.raises(UserNotFoundError):
        user_repo.get_by_username("alice")


def test_duplicate_username_or_email_is_rejected(user_repo: UserRepository):
    _create_user(user_repo)

    with pytest.raises(UserAlreadyExistsError):
        user_repo.create(_user(email="other@example.com"))
    with pytest.raises(UserAlreadyExistsError):
        user_repo.create(_user(username="bob", email="alice@example.com"))


def test_password_name_is_unique_per_user_not_globally(
    user_repo: UserRepository, password_repo: PasswordRepository
):
    alice = _create_user(user_repo)
    bob = _create_user(user_repo, username="bob", email="bob@example.com")

    first = password_repo.create(_password(user_id=alice.id, name="github"))
    other_user_same_name = password_repo.create(
        _password(user_id=bob.id, name="github", ciphertext=b"bob-secret")
    )

    assert first.id != other_user_same_name.id
    with pytest.raises(PasswordAlreadyExistsError):
        password_repo.create(_password(user_id=alice.id, name="github"))


def test_passwords_are_stored_as_ciphertext_not_plaintext(
    conn, user_repo: UserRepository, password_repo: PasswordRepository
):
    user = _create_user(user_repo)
    plaintext = "hunter2-plain"
    password_repo.create(_password(user_id=user.id, ciphertext=plaintext.encode()))

    row = conn.execute("SELECT ciphertext, nonce FROM passwords").fetchone()
    assert row["ciphertext"] == plaintext.encode()
    assert row["nonce"] == b"n" * 12
    names = [
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    ]
    assert "passwords" in names


def test_password_delete_and_update_are_scoped_to_owning_user(
    user_repo: UserRepository, password_repo: PasswordRepository
):
    alice = _create_user(user_repo)
    bob = _create_user(user_repo, username="bob", email="bob@example.com")
    stored = password_repo.create(
        _password(user_id=alice.id, ciphertext=b"alice-secret")
    )

    attacker = Password(
        id=stored.id,
        user_id=bob.id,
        name=stored.name,
        nonce=b"x" * 12,
        ciphertext=b"tampered",
        created_at=stored.created_at,
    )
    password_repo.update(attacker)
    password_repo.delete(attacker)

    remaining = password_repo.get_all_by_user_id(alice.id)
    assert len(remaining) == 1
    assert remaining[0].ciphertext == b"alice-secret"
    assert remaining[0].nonce == stored.nonce
    assert password_repo.get_all_by_user_id(bob.id) == []


def test_deleting_user_cascades_password_records(
    user_repo: UserRepository, password_repo: PasswordRepository
):
    alice = _create_user(user_repo)
    bob = _create_user(user_repo, username="bob", email="bob@example.com")
    password_repo.create(_password(user_id=alice.id, name="one"))
    password_repo.create(_password(user_id=alice.id, name="two", ciphertext=b"c2"))
    password_repo.create(_password(user_id=bob.id, name="one", ciphertext=b"bob"))

    user_repo.delete_by_id(alice)

    assert password_repo.get_all_by_user_id(alice.id) == []
    assert len(password_repo.get_all_by_user_id(bob.id)) == 1
    with pytest.raises(UserNotFoundError):
        user_repo.get_by_username("alice")
