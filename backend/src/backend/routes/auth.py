from typing import Annotated

from fastapi import APIRouter, Depends

from backend.dependencies import get_auth, require_auth
from backend.services.auth import Auth

from ..models import LoginRequest, RegisterRequest

router = APIRouter(prefix="/auth")


@router.post("/login")
def login(request: LoginRequest, auth: Annotated[Auth, Depends(get_auth)]):
    return auth.login(request.username, request.password)


@router.post("/register")
def register(request: RegisterRequest, auth: Annotated[Auth, Depends(get_auth)]):
    return auth.register(request.username, request.password)


@router.get("/id")
def get_id(user_id: Annotated[int, Depends(require_auth)]):
    return {"message": f"User ID: {user_id}"}
