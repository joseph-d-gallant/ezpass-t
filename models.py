from dataclasses import dataclass, field
from typing import Callable
import time
from questionary import Choice
import questionary

from validators import (
    ConfirmPasswordValidator,
    CreateEmailValidator,
    CreatePasswordValidator,
    CreateUsernameValidator,
    LoginPasswordValidator,
    LoginUsernameValidator,
)

#DB Related
@dataclass
class User:
    id: int | None
    username: str
    email: str
    salt: bytes
    hash: str
    
    @classmethod
    def from_row(cls, row):
        return cls(**dict(row))

#Need to seperate server models from code models, unless ignoring id
@dataclass
class Password:
    id: int
    user_id: int
    name: str
    nonce: bytes
    ciphertext: bytes
    created_at: int = field(default_factory=lambda: int(time.time()))
    

    @classmethod
    def from_row(cls, row):
        return cls(**dict(row))
    
    @classmethod
    def from_rows(cls, rows):
        passwords = []
        for row in rows:
            passwords.append(cls.from_row(row))
        return passwords

@dataclass
class Vault:
    passwords: dict[int, Password] = field(default_factory=dict)
    
    def add(self, password: Password):
        self.passwords[password.id] = password

@dataclass
class Session:
    user: User
    secret_key: bytes
    vault: Vault
    last_active: float
    authenticated: bool

@dataclass
class Menu:
    title: str
    choices: list[Choice]

#Non-DB Related
@dataclass
class UsernameField:
    placeholder: str = "USERNAME:"
    event: object = field(init=False)
    value: str = None
    validator: Callable = None
    
    def __post_init__(self):
        self.event = questionary.text(self.placeholder, validate=self.validator)

@dataclass
class PasswordField:
    placeholder: str = "PASSWORD:"
    event: object = field(init=False)
    value: str = None
    validator: Callable = None

    def __post_init__(self):
        self.event = questionary.password(self.placeholder, validate=self.validator)

@dataclass
class EmailField:
    placeholder: str = "EMAIL:"
    event: object = field(init=False)
    value: str = None
    validator: Callable = None
    
    def __post_init__(self):
        self.event = questionary.text(self.placeholder, validate=self.validator)

@dataclass
class FieldGroup:
    pass

@dataclass
class CreateUserFieldGroup(FieldGroup):
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
        self.confirm_password_field = PasswordField(
            placeholder="CONFIRM PASSWORD:",
            validator=ConfirmPasswordValidator(self.password_field),
        )

@dataclass
class LoginFieldGroup(FieldGroup):
    username_field: UsernameField = field(
        default_factory=lambda: UsernameField(validator=LoginUsernameValidator)
    )
    password_field: PasswordField = field(
        default_factory=lambda: PasswordField(validator=LoginPasswordValidator)
    )
