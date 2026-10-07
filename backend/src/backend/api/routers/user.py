from typing import Annotated

from backend.infrastructure.dependencies import require_auth
from fastapi import APIRouter, Depends

user_router = APIRouter(prefix="/user")


@user_router.get("/id")
def get_id(user_id: Annotated[int, Depends(require_auth)]):
    return {"message": f"User ID: {user_id}"}
