from typing import Annotated

from backend.api.schemas import LoginRequest, RegisterRequest
from backend.infrastructure.dependencies import get_auth_service
from backend.services.auth import Auth
from fastapi import APIRouter, Depends

auth_router = APIRouter(prefix="/auth")


@auth_router.post("/login")
def login(request: LoginRequest, auth: Annotated[Auth, Depends(get_auth_service)]):
    return auth.login(request.username, request.password)


@auth_router.post("/register")
def register(
    request: RegisterRequest, auth: Annotated[Auth, Depends(get_auth_service)]
):
    return auth.register(request.email, request.username, request.password)
