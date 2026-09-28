from fastapi import FastAPI

from backend.infrastructure.database import initialize
from backend.routes import auth

initialize()
app = FastAPI()
app.include_router(auth.router)
