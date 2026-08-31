"""Data-access layer for users and encrypted password records."""

import sqlite3

from ..models import Password, User


class UserRepository:
    """CRUD operations for user accounts."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
    
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

        if row:
            user = User.from_row(row)
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
    
    def get_by_username(self, username: str) -> dict:
        """Return all password rows for the given username, newest first."""
        rows = self.conn.execute(
            """
            SELECT passwords.*
            FROM users
            JOIN passwords
                ON users.id = passwords.user_id
            WHERE users.username = ?
            ORDER BY created_at DESC
            """,
            (username,),
        ).fetchall()

        passwords = Password.from_rows(rows)
        return passwords

    def create(self, password: Password) -> Password | bool:
        """Insert a password row and return the persisted record on success."""
        try:
            row = self.conn.execute(
                """
                INSERT INTO passwords (user_id, name, nonce, ciphertext, created_at)
                VALUES (?, ?, ?, ?, ?)
                RETURNING *
                """,
                (password.user_id, password.name, password.nonce, password.ciphertext, password.created_at),
            ).fetchone()
            self.conn.commit()
            if row:
                return Password.from_row(row)
        except sqlite3.IntegrityError as e:
            print(e)

    def update_by_id(self, password: Password):
        """Replace ciphertext and nonce for an existing password owned by the user."""
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

    def delete_by_id(self, password: Password):
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
            return True
        except sqlite3.IntegrityError as e:
            print(e)
