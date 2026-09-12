"""Application entry point: wire dependencies and start the terminal UI."""

import sys

from ezpass_t.infrastructure.crypto import Crypto
from ezpass_t.infrastructure.database.database import Database
from ezpass_t.infrastructure.database.repositories import (
    PasswordRepository,
    UserRepository,
)
from ezpass_t.services.password_manager import PasswordManager
from ezpass_t.ui.app import TerminalUI


def main():
    debug = "--debug" in sys.argv
    """Initialize storage, construct services, and run the interactive CLI."""
    db = Database()
    db.initialize()
    user_repo = UserRepository(db.conn)
    password_repo = PasswordRepository(db.conn)
    crypto = Crypto()
    password_manager = PasswordManager(user_repo, password_repo, crypto)
    terminal_ui = TerminalUI(password_manager)

    try:
        terminal_ui.run()
    finally:
        if not debug:
            # Clear sensitive output from the terminal on exit.
            terminal_ui.clear_terminal()
        else:
            # Output logs and errors
            pass


if __name__ == "__main__":
    main()
