"""Application service layer for authentication, encryption, and password vault operations."""

import os
import secrets
import smtplib
import string
import time
from datetime import datetime
from email.message import EmailMessage

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from ..infrastructure.crypto import Crypto
from ..infrastructure.database.repositories import PasswordRepository, UserRepository
from ..domain.models import User, Password, Session, Vault
from ..ui.models import LoginFieldGroup, CreateUserFieldGroup


class PasswordManager:
    """Coordinates user auth, vault encryption, and password CRUD for the active session."""

    # Idle session length in seconds before re-authentication is required.
    SESSION_TIMEOUT = 8 * 60
    
    def __init__(self, user_repo: UserRepository, password_repo: PasswordRepository, crypto: Crypto):
        self.user_repo = user_repo
        self.password_repo = password_repo
        self.crypto = crypto
        self.session = None
    
    def generate_password(self, length: int, include: str) -> str:
        """Build a random password that satisfies minimum character-class requirements."""
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        # Guarantee at least one character from each required set before filling the rest.
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(include),
        ]
        all_chars = lowercase + uppercase + digits + include
        password += [secrets.choice(all_chars) for _ in range(length - 4)]
        secrets.SystemRandom().shuffle(password)
        return "".join(password)
    
    def create_vault(self, user_id: int) -> Vault:
        """Load and assemble the user's encrypted passwords into an in-memory vault."""
        passwords = self.password_repo.get_all_by_user_id(user_id)
        vault = Vault()
        for password in passwords:
            vault.add_password(password)
        return vault

    def get_passwords(self):
        """Decrypt all vault entries and return display-ready metadata keyed by password id."""
        #Password objects exist in the vault only, dict mappings create a temporary "Password" object for displaying plaintext
        passwords = {}
        for password in self.session.vault.passwords.values():
            plaintext = self.crypto.decrypt_ciphertext(self.session.secret_key, password.nonce, password.ciphertext)
            #View representation
            passwords[password.id] = {
                "id": password.id,
                "name": password.name, 
                "plaintext": plaintext,
                "created_at": str(datetime.fromtimestamp(password.created_at))
            }
            
        return passwords 
              
    def create_password(self, name: str, length: int = 16, include: str = "?!#@$"):
        """Generate, encrypt, persist, and cache a new password entry in the vault."""
        if not name:
            return
        nonce = os.urandom(12)
        plaintext = self.generate_password(length, include)
        ciphertext = self.crypto.encrypt_plaintext(self.session.secret_key, nonce, plaintext)
        password = self.password_repo.create(Password(None, self.session.user.id, name, nonce, ciphertext))
        if password:
            self.session.vault.add_password(password)

    def update_password(self, password_id: int, plaintext: str):
        """Re-encrypt and persist an updated plaintext value for an existing entry."""
        #At minnimum you need user_id + password_id to update / delete, besides other values
        nonce = os.urandom(12)
        ciphertext = self.crypto.encrypt_plaintext(self.session.secret_key, nonce, plaintext)
        password = self.session.vault.get_password(password_id)
        password.nonce = nonce
        password.ciphertext = ciphertext
        #Update vault only after local (db) update is successful
        self.password_repo.update(password)
        self.session.vault.update_password(password_id, nonce, ciphertext)
    
    def delete_password(self, password_id: int):
        """Remove a password from persistent storage and the in-memory vault."""
        password = self.session.vault.get_password(password_id)
        self.password_repo.delete(password)
        self.session.vault.delete_password(password_id)
        
    def verify_email(self, recipient_email: str):
        """Send a one-time verification code and confirm the user's response."""
        # Stubbed for development; remove the early return to enable SMTP verification.
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
        return code_attempt == code

    def is_authenticated(self):
        """Return True when a session exists and has not exceeded the idle timeout."""
        if self.session is None:
            return False
         
        return (
            self.session.authenticated 
            and time.monotonic() - self.session.last_active
            < self.SESSION_TIMEOUT
        )
    
    def login(self, login_field_group: LoginFieldGroup) -> bool:
        """Verify credentials, derive the vault key, and open an authenticated session."""
        user = self.user_repo.get_by_username(login_field_group.username_field.value)
        if user:
            try:
                ph = PasswordHasher()
                result = ph.verify(user.hash, login_field_group.password_field.value)
                secret_key = self.crypto.derive_secret_key(user.salt, login_field_group.password_field.value)
                # Best-effort cleanup; Python does not guarantee memory wiping of strings.
                del login_field_group
                vault = self.create_vault(user.id)
                self.session = Session(user, secret_key, vault, time.monotonic(), True)
                return result
            except VerifyMismatchError:
                return False
        else:
            return False
    
    def logout(self):
        """Clear the active session and discard in-memory secrets."""
        self.session = None
    
    def create_user(self, create_field_group: CreateUserFieldGroup):
        """Hash credentials and persist a new user record."""
        ph = PasswordHasher()
        salt = os.urandom(16)
        user = User(
            id=None,
            username=create_field_group.username_field.value,
            email=create_field_group.email_field.value,
            salt=salt,
            hash=ph.hash(create_field_group.password_field.value)
        )
        self.user_repo.create(user)
    
    def delete_user(self):
        """Delete the logged-in user from the db and end the session."""
        self.user_repo.delete_by_id(self.session.user)
        self.logout()