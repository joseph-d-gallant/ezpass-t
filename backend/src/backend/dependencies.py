from collections.abc import Generator
from typing import Annotated

import psycopg
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.infrastructure.database import pool
from backend.infrastructure.repositories import UserRepository
from backend.services.auth import Auth

security = HTTPBearer()


def get_db() -> Generator[psycopg.Connection]:
    with pool.connection() as conn:
        yield conn


def get_user_repo(
    conn: Annotated[psycopg.Connection, Depends(get_db)],
) -> UserRepository:
    return UserRepository(conn)


def get_auth(user_repo: Annotated[UserRepository, Depends(get_user_repo)]) -> Auth:
    return Auth(user_repo)


def require_auth(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    auth: Annotated[Auth, Depends(get_auth)],
) -> str:
    return auth._verify_access_token(credentials.credentials)
