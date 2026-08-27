import os
import secrets
import smtplib
import string
import time
from datetime import datetime
from email.message import EmailMessage

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from db.repositories import PasswordRepository, UserRepository
from models import (
    CreateUserFieldGroup,
    LoginFieldGroup,
    Password,
    Session,
    User,
    Vault,
)


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