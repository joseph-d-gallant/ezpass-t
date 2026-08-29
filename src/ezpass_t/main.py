"""Application entry point: wire dependencies and start the terminal UI."""

from .db.database import Database
from .db.repositories import PasswordRepository, UserRepository
from .services.client import Client
from .ui.app import TerminalUI


def main():
    """Initialize storage, construct services, and run the interactive CLI."""
    db = Database()
    db.initialize()
    user_repo = UserRepository(db.conn)
    password_repo = PasswordRepository(db.conn)
    client = Client(user_repo, password_repo)
    terminal_ui = TerminalUI(client)
    
    try:
        terminal_ui.run()
    finally:
        # Clear sensitive output from the terminal on exit.
        terminal_ui.clear_terminal()


if __name__ == "__main__":
    main()
