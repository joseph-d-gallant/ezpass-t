import re

from questionary import Validator, ValidationError


class LoginUsernameValidator(Validator):
    def validate(self, document):
        text = document.text.strip()
        if not text:
            raise ValidationError(
                message="Username is required.",
                cursor_position=len(document.text),
            )


class CreateUsernameValidator(Validator):
    MIN_LENGTH = 8
    MAX_LENGTH = 32

    def validate(self, document):
        text = document.text.strip()
        if not text:
            raise ValidationError(
                message="Username is required.",
                cursor_position=len(document.text),
            )
        if len(text) < self.MIN_LENGTH:
            raise ValidationError(
                message=f"Username must be at least {self.MIN_LENGTH} characters.",
                cursor_position=len(document.text),
            )
        if len(text) > self.MAX_LENGTH:
            raise ValidationError(
                message=f"Username must be at most {self.MAX_LENGTH} characters.",
                cursor_position=len(document.text),
            )
        if not re.fullmatch(r"[A-Za-z0-9_]+", text):
            raise ValidationError(
                message="Username may only contain letters, numbers, and underscores.",
                cursor_position=len(document.text),
            )


class LoginPasswordValidator(Validator):
    def validate(self, document):
        if not document.text:
            raise ValidationError(
                message="Password is required.",
                cursor_position=len(document.text),
            )


class CreatePasswordValidator(Validator):
    MIN_LENGTH = 8

    def validate(self, document):
        text = document.text
        if not text:
            raise ValidationError(
                message="Password is required.",
                cursor_position=len(document.text),
            )
        if len(text) < self.MIN_LENGTH:
            raise ValidationError(
                message=f"Password must be at least {self.MIN_LENGTH} characters.",
                cursor_position=len(document.text),
            )
        if not re.search(r"[A-Za-z]", text):
            raise ValidationError(
                message="Password must contain at least one letter.",
                cursor_position=len(document.text),
            )
        if not re.search(r"\d", text):
            raise ValidationError(
                message="Password must contain at least one number.",
                cursor_position=len(document.text),
            )


class ConfirmPasswordValidator(Validator):
    def __init__(self, password_field):
        self.password_field = password_field

    def validate(self, document):
        if not document.text:
            raise ValidationError(
                message="Please confirm your password.",
                cursor_position=len(document.text),
            )
        if document.text != self.password_field.value:
            raise ValidationError(
                message="Passwords do not match.",
                cursor_position=len(document.text),
            )


class CreateEmailValidator(Validator):
    EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    def validate(self, document):
        text = document.text.strip()
        if not text:
            raise ValidationError(
                message="Email is required.",
                cursor_position=len(document.text),
            )
        if not self.EMAIL_PATTERN.fullmatch(text):
            raise ValidationError(
                message="Enter a valid email address.",
                cursor_position=len(document.text),
            )


create_username_validator = CreateUsernameValidator
