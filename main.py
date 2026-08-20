import ctypes
import os
import secrets
import string
import subprocess
import time

from db.database import Database
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from getpass_asterisk.getpass_asterisk import getpass_asterisk
import smtplib
from email.message import EmailMessage
import time
import questionary
from datetime import datetime
from questionary import ValidationError, Choice
from dotenv import load_dotenv
from dataclasses import dataclass, field
from typing import Callable, Any

from db.repositories import UserRepository, PasswordRepository
from models import CreateUserFieldGroup, LoginFieldGroup, Session, User, Password, FieldGroup, Vault, Menu
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding.key_bindings import Binding
from prompt_toolkit.key_binding import KeyBindings, merge_key_bindings

load_dotenv()

class Client:
    SESSION_TIMEOUT = 10 * 60
    
    def __init__(self, user_repo: UserRepository, password_repo: PasswordRepository):
        self.user_repo = user_repo
        self.password_repo = password_repo
        self.session = None
    
    def derive_secret_key(self, salt: bytes, master_password: str):
        kdf = Scrypt(
            salt=salt,
            length=32,  # 256-bit key
            n=2**14,
            r=8,
            p=1,
        )
    
        secret_key = kdf.derive(master_password.encode())
        return secret_key
    
    def encrypt_plaintext(self, nonce: bytes, plaintext: str):
        aes = AESGCM(self.session.secret_key)
        return aes.encrypt(nonce, plaintext, None)
    
    def decrypt_ciphertext(self, nonce: bytes, ciphertext: bytes) -> str:
        aes = AESGCM(self.session.secret_key)
        return aes.decrypt(nonce, ciphertext, None)
    
    def generate_password(self, length, include):
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(include),
        ]
        all_chars = lowercase + uppercase + digits + include
        password += [secrets.choice(all_chars) for _ in range(length - 4)]
        # Securely shuffle the characters
        secrets.SystemRandom().shuffle(password)
        return "".join(password)
    
    def create_vault(self, user: User) -> Vault:
        passwords = self.password_repo.get_by_username(user.username)
        vault = Vault()
        for password in passwords:
            vault.add(password)
        return vault

    def get_passwords(self):
        passwords = {}
        for password in self.session.vault.passwords.values():
            plaintext = self.decrypt_ciphertext(password.nonce, password.ciphertext).decode()
            passwords[password.id] = {
                "name": password.name, 
                "password": plaintext,
                "created_at": datetime.fromtimestamp(password.created_at)
            }
        
        return passwords 
              
    def create_password(self, name: str, length: int = 10, include: str = "?!#@$"):
        nonce = os.urandom(12)
        plaintext = self.generate_password(length, include)
        ciphertext = self.encrypt_plaintext(nonce, plaintext.encode())
        password = self.password_repo.create(Password(None, self.session.user.id, name, nonce, ciphertext))
        if password:
            self.session.vault.add(password)

    def update_password(self, password_id: int, plaintext: str):
        nonce = os.urandom(12)
        ciphertext = self.encrypt_plaintext(nonce, plaintext.encode())
        password = self.session.vault.passwords[password_id]
        password.nonce = nonce
        password.ciphertext = ciphertext
        self.password_repo.update_by_id(password)
    
    def delete_password(self, password_id: int):
        if self.password_repo.delete_by_id(self.session.vault.passwords[password_id]):
            del self.session.vault.passwords[password_id]
        
    def verify_email(self, recipient_email: str):
        return True
        code = str(secrets.randbelow(900000) + 100000)
        msg = EmailMessage()
    
        msg["Subject"] = "Verification Code - (ezpass-t)"
        msg["From"] = "noreply@ezpass-t.dev"
        msg["To"] = recipient_email
    
        msg.set_content(f"""
        Your verification code is:
    
        {code}
        """)
        with smtplib.SMTP("smtp-relay.brevo.com", 587) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(
                BREVO_EMAIL,
                BREVO_PASSWORD
            )
            smtp.send_message(msg)
        
        print("A verification code was sent to your email.")
        code_attempt = input("Code: ")
        if code_attempt == code:
            return True
        else:
            return False

    def is_authenticated(self):
        if self.session is None:
            return False
         
        return (
            self.session.authenticated 
            and time.monotonic() - self.session.last_active
            < self.SESSION_TIMEOUT
        )
    
    def login(self, login_field_group: LoginFieldGroup) -> bool:
        user = self.user_repo.get_by_username(login_field_group.username_field.value)
        if user:
            try:
                ph = PasswordHasher()
                result = ph.verify(user.hash, login_field_group.password_field.value)
                secret_key = self.derive_secret_key(user.salt, login_field_group.password_field.value)
                del login_field_group #Not secure, consider a different language for clearing sensitive data.
                vault = self.create_vault(user)
                self.session = Session(user, secret_key, vault, time.monotonic(), True)
                return result
            except VerifyMismatchError:
                print("Invalid Password.")
        else:
            print("User Not Found.")
            return False
    
    def logout(self):
        self.session = None
    
    def create_user(self, create_field_group: CreateUserFieldGroup):
        ph = PasswordHasher()
        salt = os.urandom(16)
        user = User(
            id=None,
            username=create_field_group.username_field.value,
            email=create_field_group.email_field.value,
            salt=salt,
            hash=ph.hash(create_field_group.password_field.value)
        )
        result = self.user_repo.create(user)
        print(result)
    
    def delete_user(self):
        pass
        
class TerminalUI:
    
    #Could create hook to generate values as needed.
    MENU_CONFIG = {
        "root_menu": {
            "title": "ezpass",
            "choices": [
                {"title": "Login", "action": "login"},
                {"title": "Create User", "action": "create_user"},
                {"title": "Delete User", "action": "delete_user"}
            ]
        },
        "user_menu": {
            "title": "ezpass/user",
            "choices": [
                {"title": "View", "action": "view_passwords"},
                {"title": "Create", "action": "create_password"},
                {"title": "Update", "action": "update_password"},
                {"title": "Delete", "action": "delete_password"}
            ]
        }
    }
    
    NAV_CONTROLS = "            [ ← Back  ↑ Up / ↓ Down  Select → ]"
    
    def __init__(self, client: Client):
        self.client = client
        self.root_menu: Menu
        self.user_menu: Menu
        self.exit_flag = False
        
    def add_custom_bindings(self, question: questionary.Question):
        binding = Binding(
            keys=("left",),
            handler=lambda event: event.app.exit(result=None),
            eager=True,
        )
        question.application.key_bindings.bindings.insert(0, binding)
        
        return question
    
    def get_fields(self, field_group: FieldGroup) -> FieldGroup | None:
        counter = 0
        attrs = list(vars(field_group).items())
        while counter < len(vars(field_group)):
            value = self.add_custom_bindings(attrs[counter][1].event).ask()
            field = attrs[counter][1]
            if value == None and counter == 0:
                field.value = None
                return None
            elif value == None:
                field.value = None
                print("\033[1A\033[2K", end="")
                print("\033[1A\033[2K", end="")
                counter -= 1
            else:
                field.value = value
                counter += 1
        return field_group
    
    def build_display_menus(self):
        for key, values in self.MENU_CONFIG.items():
            choices = []
            for value in self.MENU_CONFIG[key]["choices"]:
                dispatch_table = self.get_dispatch_table()
                if value["action"] in dispatch_table:
                    choice = Choice(title=value["title"], value=dispatch_table[value["action"]])
                    choices.append(choice) 
            menu = Menu(title=values["title"], choices=choices)
            setattr(self, key, menu)
    
    def get_dispatch_table(self):
        return {
            "login": self.login,
            "create_user": self.create_user,
            "delete_user": self.delete_user,
            "view_passwords": self.view_passwords,
            "create_password": self.create_password,
            "update_password": self.update_password,
            "delete_password": self.delete_password
        }
    
    def build_password_menu(self, passwords: dict) -> Menu:
        choices = []
        tabs = "            "
        for password_id, value in passwords.items():
            choice = Choice(title=f"{str(password_id) + tabs}{value["name"] + tabs}{value["password"]+ tabs}{str(value["created_at"]) + tabs}", value=password_id)
            choices.append(choice)
        return Menu(title="ezpass/user/passwords", choices=choices)
    
    def login(self):
        while not self.client.is_authenticated():
            login_field_group = LoginFieldGroup()
            login_field_group = self.get_fields(login_field_group)
            if login_field_group:
                self.is_loggedin = self.client.login(login_field_group)
            elif login_field_group is None:
                return
        
    def create_user(self):
        create_user_field_group = CreateUserFieldGroup()
        while True:
            create_user_field_group = self.get_fields(create_user_field_group)
            if create_user_field_group:
                self.client.create_user(create_user_field_group)
            return
  
    def delete_user(self):
        pass
    
    def view_passwords(self):
        if self.client.is_authenticated():
            passwords = self.client.get_passwords()
            #Print pretty with rich
            print(passwords)
            return passwords
    
    def create_password(self):
        password_name = questionary.text("ID Name:").ask()
        use_recommended_params = questionary.confirm("Use recommended parameters?").ask()
        if use_recommended_params:
            self.client.create_password(password_name)
        else:
            length = questionary.text("Desired Password Length:").ask()
            include = questionary.text("Included Special Characters:").ask()
            self.client.create_password(password_name, length, include)
        
    def update_password(self):
        if self.client.is_authenticated():
            passwords = self.view_passwords()
            password_menu = self.build_password_menu(passwords)
            #can nest selects, but implement with prompt.toolkit
            if passwords:
                password_id = questionary.select(
                    message=password_menu.title,
                    choices=password_menu.choices
                ).ask()
                plaintext = questionary.text("Update", passwords[password_id]["password"]).ask()
                self.client.update_password(password_id, plaintext)
            
    
    def delete_password(self):
        if self.client.is_authenticated():
            passwords = self.view_passwords()
            password_menu = self.build_password_menu(passwords)
            #can nest selects, but implement with prompt.toolkit
            if passwords:
                password_id = questionary.select(
                    message=password_menu.title,
                    choices=password_menu.choices
                ).ask()
                self.client.delete_password(password_id)
    
    def display_root_menu(self):
        method = self.add_custom_bindings(
            questionary.select(
                message=self.root_menu.title,
                choices=self.root_menu.choices,
                instruction=self.NAV_CONTROLS
            )
        ).ask()
        if callable(method):
            method()
        else:
            self.exit_flag = True
        
    def display_user_menu(self):
        method = self.add_custom_bindings(
            questionary.select(
                message=self.user_menu.title,
                choices=self.user_menu.choices,
                instruction=self.NAV_CONTROLS
            )
        ).ask()
        if callable(method):
            method()
        else:
            self.client.logout()
        
    def run(self):
        self.build_display_menus()
        while self.exit_flag == False:
            if self.client.is_authenticated():
                self.display_user_menu()
            else:
                self.display_root_menu()
    
    def clear_terminal(self):
        command = "cls" if os.name == "nt" else "clear"
        subprocess.run(command, shell=True)
    
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