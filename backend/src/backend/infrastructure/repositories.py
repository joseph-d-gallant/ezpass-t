from psycopg import Connection, IntegrityError


class UserRepository:
    def __init__(self, conn: Connection):
        self.conn = conn

    def get_by_username(self, username: str):
        with self.conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    SELECT *
                    FROM users
                    WHERE username = %s
                    """,
                    (username,),
                )
                return cursor.fetchone()
            except IntegrityError as e:
                print(e)

    def create(self, username: str, password_hash: str):
        with self.conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash)
                    VALUES (%s, %s)
                    RETURNING id, username
                    """,
                    (username, password_hash),
                )
                return cursor.fetchone()
            except IntegrityError as e:
                print(e)
