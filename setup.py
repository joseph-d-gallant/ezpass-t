import sqlite3
from pathlib import Path

APP_NAME = "Ezpass"

# Windows user-specific application data folder
data_dir = Path.home() / "AppData" / "Local" / APP_NAME / "data"

# Create folders if they don't exist
data_dir.mkdir(parents=True, exist_ok=True)

# Database location
db_path = data_dir / "app.db"

conn = sqlite3.connect(db_path)
conn.execute("PRAGMA foreign_keys = ON")
conn.row_factory = sqlite3.Row
cursor = conn.cursor()


def create_tables():
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            salt BLOB NOT NULL,
            hash TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            nonce BLOB,
            password_id TEXT NOT NULL,
            password BLOB NOT NULL,
            
            FOREIGN KEY(user_id) 
                REFERENCES users(id)
                ON DELETE CASCADE,
            UNIQUE (user_id, password_id)
        )
    """)
    conn.commit()


def intialize():
    try:
        create_tables()
        return conn, cursor
    except Exception as e:
        print(e)
