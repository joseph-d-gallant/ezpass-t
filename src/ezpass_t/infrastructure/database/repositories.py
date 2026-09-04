"""Data-access layer for users and encrypted password records."""

import sqlite3

from ...domain.models import User, Password
from .models import UserRecord, PasswordRecord

#Convert domain objects to records to save, translate rows to records and create new objects from those records
class UserRepository:
    """CRUD operations for user accounts."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _row_to_record(self, row) -> UserRecord:
        return UserRecord(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            salt=row["salt"],
            hash=row["hash"]
        )

    def _record_to_user(self, user_record: UserRecord) -> User:
        return User(
            id=user_record.id,
            username=user_record.username,
            email=user_record.email,
            salt=user_record.salt,
            hash=user_record.hash
        )
    
    def get_by_username(self, username: str) -> User | None:
        """Fetch a single user row by username, or None if not found."""
        row = self.conn.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if row is None:
            return None

        user_record = self._row_to_record(row)
        user = self._record_to_user(user_record)
        return user

    
    def create(self, user: User) -> str:
        """Insert a new user and return a human-readable status message."""
        try:
            self.conn.execute(
                """
                INSERT INTO users (username, email, salt, hash)
                VALUES (?, ?, ?, ?)
                """,
                (user.username, user.email, user.salt, user.hash),
            )
            self.conn.commit()
            return "User created."
        except sqlite3.IntegrityError:
            return "User exists already."

    def delete_by_id(self, user: User):
        """Delete a user; related passwords cascade via foreign key rules."""
        self.conn.execute(
            """DELETE FROM users
            WHERE id = ?
            """,
            (user.id,)
        )
        self.conn.commit()


class PasswordRepository:
    """CRUD operations for encrypted password entries."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _row_to_record(self, row) -> PasswordRecord:
        #Future proof db changes without needing to change Password (Password is owned by the domain)
        return PasswordRecord(
            id=row["id"],
            user_id=row["user_id"],
            name=row["name"],
            nonce=row["nonce"],
            ciphertext=row["ciphertext"],
            created_at=row["created_at"]
        )

    def _record_to_password(self, password_record: PasswordRecord) -> Password:
        #Truncate record to create a password with less attrs.
        return Password(
            id=password_record.id,
            user_id=password_record.user_id,
            name=password_record.name,
            nonce=password_record.nonce,
            ciphertext=password_record.ciphertext,
            created_at=password_record.created_at
        )

    def _password_to_record(self, password: Password) -> PasswordRecord:
        #Add default values that diff from Password structure and matter to db.
        return PasswordRecord(
            id=password.id,
            user_id=password.user_id,
            name=password.name,
            nonce=password.nonce,
            ciphertext=password.ciphertext,
            created_at=password.created_at
        )
    
    def get_all_by_user_id(self, user_id: int) -> list[Password]:
        """Return all password rows for the given username, newest first."""
        rows = self.conn.execute(
            """
            SELECT *
            FROM passwords
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,),
        ).fetchall()

        passwords = []
        for row in rows:
            password_record = self._row_to_record(row)
            password = self._record_to_password(password_record)
            passwords.append(password)

        return passwords

    def create(self, password: Password) -> Password | None:
        """Insert a password row and return the persisted record on success."""
        password_record = self._password_to_record(password)
        try:
            row = self.conn.execute(
                """
                INSERT INTO passwords (user_id, name, nonce, ciphertext, created_at)
                VALUES (?, ?, ?, ?, ?)
                RETURNING *
                """,
                (password_record.user_id, password_record.name, password_record.nonce, password_record.ciphertext, password_record.created_at),
            ).fetchone()
            self.conn.commit()
            if row is None:
                return None

            new_password_record = self._row_to_record(row)
            password = self._record_to_password(new_password_record)
            return password
            
        except sqlite3.IntegrityError as e:
            print(e)
            return None

    def update(self, password: Password) -> None:
        """Replace ciphertext and nonce for an existing password owned by the user."""
        try:
            self.conn.execute(
                """
                UPDATE passwords
                SET ciphertext = ?,
                    nonce = ?
                WHERE id = ?
                    AND user_id = ?
                """,
                (password.ciphertext, password.nonce, password.id, password.user_id),
            )
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(e)


    def delete(self, password: Password) -> None:
        """Delete a password row scoped to its owning user."""
        try:
            self.conn.execute(
                """
                DELETE FROM passwords
                WHERE id= ?
                    AND user_id = ?
                """,
                (password.id, password.user_id),
            )
            self.conn.commit()
            print("Password Deleted.")
        except sqlite3.IntegrityError as e:
            print(e)
