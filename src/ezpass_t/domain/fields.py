from collections.abc import Callable
from dataclasses import dataclass, field

import questionary
from questionary import Choice

from ..ui.validators import (
    ConfirmPasswordValidator,
    CreateEmailValidator,
    CreatePasswordValidator,
    CreateUsernameValidator,
    LoginPasswordValidator,
    LoginUsernameValidator,
)


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
class CreatePasswordFieldGroup(FieldGroup):...

@dataclass
class LoginFieldGroup(FieldGroup):
    """Login flow fields with minimal required-input validation."""

    username_field: UsernameField = field(
        default_factory=lambda: UsernameField(validator=LoginUsernameValidator)
    )
    password_field: PasswordField = field(
        default_factory=lambda: PasswordField(validator=LoginPasswordValidator)
    )