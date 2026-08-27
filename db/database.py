import os
import sqlite3
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
DB_FILENAME = os.getenv("DB_FILENAME")
APP_NAME = "ezpass-t"

class Database:
    def __init__(self):
        self.conn = self.setup_conn()

    def setup_conn(self):
        data_dir_path = Path.home() / "AppData" / "Local" / APP_NAME / "data"
        data_dir_path.mkdir(parents=True, exist_ok=True)
        db_path = data_dir_path / DB_FILENAME
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                salt BLOB NOT NULL,
                hash TEXT NOT NULL
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                nonce BLOB,
                ciphertext BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                
                FOREIGN KEY(user_id) 
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                UNIQUE (user_id, name)
            )
        """)
        self.conn.commit()