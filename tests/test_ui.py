"""Critical security tests for input validation and TerminalUI auth flows."""

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from questionary import ValidationError

from ezpass_t.services.exceptions import (
    AuthenticationError,
    SessionIsExpiredError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from ezpass_t.ui.app import TerminalUI
from ezpass_t.ui.validators import (
    ConfirmPasswordValidator,
    CreateEmailValidator,
    CreatePasswordValidator,
    CreateUsernameValidator,
)


class _Document:
    def __init__(self, text: str):
        self.text = text


def _assert_invalid(validator, text: str):
    with pytest.raises(ValidationError):
        validator.validate(_Document(text))


def test_create_username_validator_enforces_length_and_safe_charset():
    validator = CreateUsernameValidator()
    validator.validate(_Document("valid_user"))

    _assert_invalid(validator, "")
    _assert_invalid(validator, "short")
    _assert_invalid(validator, "a" * 33)
    _assert_invalid(validator, "bad user")
    _assert_invalid(validator, "admin'; DROP TABLE users;--")
    _assert_invalid(validator, "../etc/passwd")


def test_create_password_validator_requires_strength_and_does_not_strip():
    validator = CreatePasswordValidator()
    validator.validate(_Document("Password1"))

    _assert_invalid(validator, "")
    _assert_invalid(validator, "short1A")
    _assert_invalid(validator, "NoDigitsHere")
    _assert_invalid(validator, "12345678")
    # Leading/trailing spaces are part of the secret and must not be stripped.
    validator.validate(_Document(" Password1"))


def test_confirm_password_and_email_validators_reject_mismatches_and_invalid_mail():
    password_field = SimpleNamespace(value="Password1")
    confirm = ConfirmPasswordValidator(password_field)
    confirm.validate(_Document("Password1"))
    _assert_invalid(confirm, "")
    _assert_invalid(confirm, "Password2")

    email = CreateEmailValidator()
    email.validate(_Document("user@example.com"))
    _assert_invalid(email, "")
    _assert_invalid(email, "not-an-email")
    _assert_invalid(email, "user@nodot")
    _assert_invalid(email, "user example.com")


@pytest.fixture
def ui() -> TerminalUI:
    terminal_ui = TerminalUI(Mock())
    terminal_ui.clear_terminal = Mock()
    terminal_ui.display_error = Mock()
    terminal_ui.display_notification = Mock()
    return terminal_ui


def _credential_fields(username: str, password: str):
    return SimpleNamespace(
        username_field=SimpleNamespace(value=username),
        password_field=SimpleNamespace(value=password),
    )


def test_login_uses_generic_error_and_does_not_authenticate_on_failure(ui: TerminalUI):
    fields = _credential_fields("alice", "wrong")
    ui.password_manager.is_authenticated.side_effect = [False, False, False]
    ui.password_manager.login.side_effect = AuthenticationError
    ui._get_fields = Mock(side_effect=[fields, None])

    with patch("ezpass_t.ui.app.LoginFieldGroup", return_value=fields):
        ui.login()

    ui.display_error.assert_called_once()
    message = ui.display_error.call_args.args[0]
    assert "incorrect" in message.lower()
    assert "alice" not in message
    assert ui.is_active is False


def test_login_unknown_user_is_indistinguishable_from_bad_password(ui: TerminalUI):
    fields = _credential_fields("missing", "Password1")
    ui.password_manager.is_authenticated.side_effect = [False, False]
    ui.password_manager.login.side_effect = UserNotFoundError
    ui._get_fields = Mock(side_effect=[fields, None])

    with patch("ezpass_t.ui.app.LoginFieldGroup", return_value=fields):
        ui.login()

    ui.display_error.assert_called_once()
    assert (
        "username or password is incorrect"
        in ui.display_error.call_args.args[0].lower()
    )
    assert "not found" not in ui.display_error.call_args.args[0].lower()


def test_expired_session_forces_logout_and_delete_user_requires_confirmation(
    ui: TerminalUI,
):
    ui.password_manager.get_passwords.side_effect = SessionIsExpiredError
    ui.logout = Mock()

    ui.read_passwords()
    ui.update_password()
    ui.delete_password()

    assert ui.logout.call_count == 3
    ui.password_manager.delete_password.assert_not_called()
    ui.password_manager.update_password.assert_not_called()

    ui.login = Mock(return_value=None)
    with patch("ezpass_t.ui.app.questionary.confirm") as confirm:
        ui.delete_user()
        confirm.assert_not_called()
    ui.password_manager.delete_user.assert_not_called()


def test_create_user_surfaces_duplicate_account_without_creating_session(
    ui: TerminalUI,
):
    fields = Mock()
    ui._get_fields = Mock(side_effect=[fields, None])
    ui.password_manager.create_user.side_effect = UserAlreadyExistsError

    with patch("ezpass_t.ui.app.CreateUserFieldGroup", return_value=fields):
        ui.create_user()

    ui.display_error.assert_called_once()
    ui.display_notification.assert_not_called()
    assert ui.is_active is False
