import setup
from getpass_asterisk.getpass_asterisk import getpass_asterisk
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyperclip
import subprocess
import ctypes
import secrets
import string
import time
from sqlite3 import IntegrityError

def clear_clipboard():
    for remaining in range(60, -1, -1):
        print(f"\r\033[2KCleaning up the Clipboard in: {remaining}s", end="", flush=True)
        time.sleep(1)

    clear_terminal()
    print("Clipboard Cleared!")
    time.sleep(1)
    ctypes.windll.user32.OpenClipboard(0)
    ctypes.windll.user32.EmptyClipboard()
    ctypes.windll.user32.CloseClipboard()

def clear_terminal():
    command = 'cls' if os.name == 'nt' else 'clear'
    subprocess.run(command, shell=True)
    

def derive_key(salt, master_password):
    kdf = Scrypt(
    salt=salt,
    length=32,       # 256-bit key
    n=2**14,
    r=8,
    p=1,
    )

    key = kdf.derive(master_password.encode())
    return key

def encrypt(user, password):
    aes = AESGCM(user["key"])
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(
        nonce,
        password,
        None
    )
    return ciphertext, nonce

def decrypt(user, passwords):
    aes = AESGCM(user["key"])
    for value in passwords.values():
        value["password"] = aes.decrypt(value["nonce"], value["password"], None)
    return passwords    

def get_user(username_attempt):
    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username_attempt,)
    )
    
    user = cursor.fetchone()
    if user:
        return dict(user)

def get_passwords(user):
    cursor.execute(
        """
        SELECT passwords.*
        FROM users
        JOIN passwords
            ON users.id = passwords.user_id
        WHERE users.username = ?
        """,
        (user["username"],)
    )
    passwords = {
        password["password_id"]: {"id": password["id"], "user_id": password["user_id"], "nonce": password["nonce"], "password": password["password"]}
        for password in cursor.fetchall()
    }
    return passwords

def create_user():
    ph = PasswordHasher()
    new_username = input("NEW USERNAME: ")
    salt = os.urandom(16)
    new_master_password = input("NEW PASSWORD: ")
    confirm_master_password = input("CONFIRM NEW PASSWORD: ")
    if new_master_password == confirm_master_password:
        try:
            cursor.execute(
                """
                INSERT INTO users (username, salt, hash)
                VALUES (?, ?, ?)
                """,
                (new_username, salt, ph.hash(new_master_password))
            )
            conn.commit()
            print("User Created.")
        except IntegrityError:
            print("Username exists.")
    else:
        return

def delete_user(user):
    confirm_deletion = input("Are you sure you want to delete your account? [y/N]: ")
    if confirm_deletion == "y":
        cursor.execute(
        "DELETE FROM users WHERE id = ?",
        (user["id"],)
        )
        conn.commit()
    else:
        return

def generate_password(len=16, special_chars="?#@!$&"):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits

    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special_chars),
    ]

    all_chars = lowercase + uppercase + digits + special_chars

    password += [
        secrets.choice(all_chars)
        for _ in range(len - 4)
    ]

    # Securely shuffle the characters
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)

def login():
    login_attempts = 0
    while True:
        clear_terminal()
        username_attempt = input("\nUSERNAME: ")
        user = get_user(username_attempt)
        if user:
            master_password_attempt = getpass_asterisk("PASSWORD: ")
            ph = PasswordHasher()
            stored_hash = user["hash"]
            try:
                result = ph.verify(stored_hash, master_password_attempt)
                user["master"] = master_password_attempt
                return user, result
            except VerifyMismatchError:
                print("Invalid Password.")
                login_attempts += 1
        elif login_attempts >= 2:
            print("User account not found.")
            choice_selected = input("\nWould you like to return to the main menu? [y/N]: ")
            if choice_selected == "y":
                return None, False
        else:
            print("User account not found.")
            time.sleep(2)
            login_attempts += 1

def display_user_menu():
    print("""
        ezpass/user/passwords
        
            1. Read / Copy
            2. Create
            3. Update
            4. Delete
            
        """)

def display_main_menu():
    print("""
    ezpass/main
    
        1. Login
        2. Create New User
        3. Delete User
        
    """)

def read(user, default_behavior=None):
    clear_terminal()
    passwords = get_passwords(user)
    if not passwords:
        print("Hmmm, it looks like you don't have any passwords yet.")
        time.sleep(2)
        return None, None
    else:
        passwords = decrypt(user, passwords)
        if passwords:
            current_passwords = {}
            print("ID", "\t\tNAME", "\t\t\tPASSWORD\n")
            for key, value in passwords.items():
                current_passwords[value["id"]] = value["password"].decode()
                print(str(value["id"]), "\t\t" + key, "\t\t\t" + value["password"].decode())
            if default_behavior == "PATCH":
                return current_passwords, passwords
            elif default_behavior == "DEL":
                return passwords, True
            else:
                try:
                    copy_id = int(input("\nCopy by ID: "))
                    pyperclip.copy(current_passwords[copy_id])
                    clear_terminal()
                    print("\nCopied to clipboard!")
                    clear_clipboard()
                except ValueError:
                    return
        else:
            print("An error has occured while decrypting.")
    
def create(user):
    clear_terminal()
    password_id = input("Password ID: ")
    pref = input("Configure password generation manually? [y/N]: ")
    len = 0
    if pref == "y":
        while len < 12 or len > 24:
            len = int(input("Desired Length: "))
            if len < 12 or len > 24:
                print("Length must be between 8 and 24 characters long.")
        special_chars = input("Included Special Characters/Symbols (Ex. #$%&@): ")
        password = generate_password(len=len, special_chars=special_chars)
    else:
        password = generate_password()
    
    ciphertext, nonce = encrypt(user, password.encode())
    try: 
        cursor.execute(
            """
            INSERT INTO passwords (user_id, password_id, nonce, password)
            VALUES (?, ?, ?, ?)
            """,
            (user["id"], password_id, nonce, ciphertext)
        )
        conn.commit()
    except IntegrityError:
        clear_terminal()
        print("Password with that id already exists.")
        time.sleep(2)

def update(user):
    passwords, unformatted_passwords = read(user, "PATCH")
    if passwords and unformatted_passwords:
        update_id = int(input("\nUpdate by ID: "))
        pyperclip.copy(passwords[update_id])
        updated_password = input("Press (CTRL + V) to Edit, then ENTER to save changes: ")
        ciphertext, nonce = encrypt(user, updated_password.encode())
        for key, value in unformatted_passwords.items():
            if update_id == value["id"]:
                print(key, value["user_id"], ciphertext, nonce)
                cursor.execute(
                    """
                    UPDATE passwords
                    SET password = ?,
                        nonce = ?
                    WHERE user_id = ?
                        AND password_id = ?
                    """,
                    (ciphertext, nonce, value["user_id"], key)
                )
                conn.commit()
        pyperclip.copy("")

def delete(user):
    passwords, temp = read(user, "DEL")
    if passwords and temp:
        try:
            delete_id = int(input("\nDelete by ID: "))
        except ValueError:
            return
        for key, value in passwords.items():
            if delete_id == value["id"]:
                confirm_delete = input(f"Are you sure you want to delete '{key}'? [y/N]: ")
                if confirm_delete == "N":
                    return
                cursor.execute(
                    """
                    DELETE FROM passwords
                    WHERE user_id = ?
                    AND password_id = ?
                    """,
                    (value["user_id"], key)
                )
                conn.commit()    

def main():
    is_authenticated = False
    while is_authenticated == False:
        clear_terminal()
        display_main_menu()
        menu_selection = input("Choose an option: ")
        if menu_selection == "1":
            user, is_authenticated = login()
            if is_authenticated:
                user["key"] = derive_key(user["salt"], user["master"])
        elif menu_selection == "2":
            create_user()
        elif menu_selection == "3":
            user, is_authenticated = login()
            if is_authenticated:
                delete_user(user)
                is_authenticated = False
    while is_authenticated:
        clear_terminal()
        display_user_menu()
        menu_selection = input("Choose an option: ")
        if menu_selection == "1":
            read(user, None)
        elif menu_selection == "2":
            create(user)
        elif menu_selection == "3":
            update(user)
        elif menu_selection == "4":
            delete(user)
    

if __name__ == "__main__":
    conn, cursor = setup.intialize()
    main()
    conn.close()
