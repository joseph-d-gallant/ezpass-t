"""Shared domain models for persistence, sessions, menus, and form input."""

import time
from collections.abc import Callable
from dataclasses import dataclass, field

import questionary
from questionary import Choice

from ui.validators import (
    ConfirmPasswordValidator,
    CreateEmailValidator,
    CreatePasswordValidator,
    CreateUsernameValidator,
    LoginPasswordValidator,
    LoginUsernameValidator,
)

# --- Persistence and session models ---

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


@dataclass
class Vault:
    """In-memory index of decrypted password metadata keyed by password id."""

    passwords: dict[int, Password] = field(default_factory=dict)
    
    def add(self, password: Password):
        """Insert or replace a password entry in the vault cache."""
        self.passwords[password.id] = password


@dataclass
class Session:
    """Authenticated runtime state, including derived encryption key and vault."""

    user: User
    secret_key: bytes
    vault: Vault
    last_active: float
    authenticated: bool


@dataclass
class Menu:
    """Questionary menu definition pairing a title with selectable choices."""

    title: str
    choices: list[Choice]


# --- Form input models ---

@dataclass
class UsernameField:
    """Prompt wrapper for collecting and validating a username."""

    placeholder: str = "USERNAME:"
    event: object = field(init=False)
    value: str = None
    validator: Callable = None
    
    def __post_init__(self):
        self.event = questionary.text(self.placeholder, validate=self.validator)


@dataclass
class PasswordField:
    """Prompt wrapper for collecting and validating a masked password."""

    placeholder: str = "PASSWORD:"
    event: object = field(init=False)
    value: str = None
    validator: Callable = None

    def __post_init__(self):
        self.event = questionary.password(self.placeholder, validate=self.validator)


@dataclass
class EmailField:
    """Prompt wrapper for collecting and validating an email address."""

    placeholder: str = "EMAIL:"
    event: object = field(init=False)
    value: str = None
    validator: Callable = None
    
    def __post_init__(self):
        self.event = questionary.text(self.placeholder, validate=self.validator)


@dataclass
class FieldGroup:
    """Base type for ordered collections of input fields."""



@dataclass
class CreateUserFieldGroup(FieldGroup):
    """Registration flow fields with stricter validation rules."""

    username_field: UsernameField = field(
        default_factory=lambda: UsernameField(
            placeholder="NEW USERNAME:",
            validator=CreateUsernameValidator,
        )
    )
    email_field: EmailField = field(
        default_factory=lambda: EmailField(
            placeholder="NEW EMAIL:",
            validator=CreateEmailValidator,
        )
    )
    password_field: PasswordField = field(
        default_factory=lambda: PasswordField(
            placeholder="NEW PASSWORD:",
            validator=CreatePasswordValidator,
        )
    )
    confirm_password_field: PasswordField = field(init=False)

    def __post_init__(self):
        # Confirmation depends on the primary password field value.
        self.confirm_password_field = PasswordField(
            placeholder="CONFIRM PASSWORD:",
            validator=ConfirmPasswordValidator(self.password_field),
        )


@dataclass
class LoginFieldGroup(FieldGroup):
    """Login flow fields with minimal required-input validation."""

    username_field: UsernameField = field(
        default_factory=lambda: UsernameField(validator=LoginUsernameValidator)
    )
    password_field: PasswordField = field(
        default_factory=lambda: PasswordField(validator=LoginPasswordValidator)
    )
