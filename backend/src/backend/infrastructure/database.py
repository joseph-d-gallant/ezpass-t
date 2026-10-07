import os

from dotenv import load_dotenv
from psycopg_pool import ConnectionPool

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")


pool = ConnectionPool(conninfo=DATABASE_URL)


def initialize() -> None:
    with pool.connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)
