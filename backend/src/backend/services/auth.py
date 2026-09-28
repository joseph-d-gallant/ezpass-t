import os
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv
from fastapi import HTTPException

from backend.infrastructure.repositories import UserRepository

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")


# Should move api concerns out of auth
class Auth:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    def _verify_access_token(self, token: str):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = payload.get("sub")
            if user_id is None:
                raise HTTPException(status_code=401, detail="Invalid access token")
            return int(user_id)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Access token expired")
        except jwt.InvalidSignatureError:
            raise HTTPException(status_code=401, detail="Invalid access token")

    def _create_access_token(self, user_id: int):
        now = datetime.now(UTC)

        payload = {"sub": str(user_id), "iat": now, "exp": now + timedelta(minutes=10)}
        return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    def login(self, username: str, password: str):
        try:
            user = self.user_repo.get_by_username(username)
            ph = PasswordHasher()
            if ph.verify(user[2], password):
                access_token = self._create_access_token(user[0])
                return {"access_token": access_token, "token_type": "bearer"}
        except VerifyMismatchError:
            return {"message": "failed to login."}

    def register(self, username: str, password: str):
        ph = PasswordHasher()
        password_hash = ph.hash(password)
        if self.user_repo.create(username, password_hash):
            return {"message": "User created."}
        else:
            return {"message": "Failed to create user."}
