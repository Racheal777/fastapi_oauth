import os
from fastapi import FastAPI
from auth import router as auth_router, init_oauth
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

   # Add this to a script or to your main.py (run once)
from models import Base
from database import engine
import asyncio

# async def create_tables():
#     async with engine.begin() as conn:
#         await conn.run_sync(Base.metadata.create_all)

# asyncio.run(create_tables())

app = FastAPI()

secret_key = os.getenv("SECRET_KEY") or "your-secret-key"

app.add_middleware(SessionMiddleware, secret_key=secret_key)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://ui-oauth-integration.vercel.app"],  # Your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/v1/auth")

init_oauth(app) 