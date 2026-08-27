from db.database import Database
from db.repositories import PasswordRepository, UserRepository
from services.client import Client
from ui.app import TerminalUI


#Replace questionary with prompt tool kit for more control
def main():
    db = Database()
    db.initialize()
    user_repo = UserRepository(db.conn)
    password_repo = PasswordRepository(db.conn)
    client = Client(user_repo, password_repo)
    terminal_ui = TerminalUI(client)
    terminal_ui.run()

if __name__ == "__main__":
    main()