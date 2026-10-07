from fastapi import FastAPI

from backend.api.routers.auth import auth_router
from backend.api.routers.user import user_router
from backend.infrastructure.database import initialize

initialize()
app = FastAPI()
app.include_router(auth_router)
app.include_router(user_router)
