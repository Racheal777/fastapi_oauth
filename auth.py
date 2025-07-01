from fastapi import APIRouter, Depends, Request, HTTPException, status, FastAPI, Cookie
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError
from database import get_db
from models import User
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from typing import Optional
from jose import jwt, JWTError
import os
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from authlib.integrations.starlette_client import OAuth
from starlette.responses import RedirectResponse
from starlette.requests import Request as StarletteRequest

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

# Attach OAuth to app state on startup
def create_oauth():
    oauth = OAuth()
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile'
        }
    )
    return oauth

# This will be called in main.py

def init_oauth(app: FastAPI):
    app.state.oauth = create_oauth()

# In main.py, after app creation, add:
# from auth import init_oauth
# init_oauth(app)

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str] = None

    class Config:
        orm_mode = True

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

@router.post("/register", response_model=UserResponse)
async def register(user: UserRegister, db: AsyncSession = Depends(get_db)):
    # Check if user already exists
    result = await db.execute(select(User).where(User.email == user.email))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = User(
        email=user.email,
        hashed_password=hash_password(user.password),
        full_name=user.full_name
    )
    db.add(db_user)
    try:
        await db.commit()
        await db.refresh(db_user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Registration failed")
    return db_user

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    from datetime import datetime, timedelta
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY is not set")
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class UserLogin(BaseModel):
    email: EmailStr
    password: str

@router.post("/login")
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == user.email))
    db_user = result.scalar_one_or_none()
    if not db_user or not getattr(db_user, "hashed_password", None):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token({"sub": str(db_user.id), "email": db_user.email})
    response = JSONResponse(content={"access_token": access_token, "token_type": "bearer"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False  # Set to True in production with HTTPS
    )
    return response

@router.get("/google/login")
async def google_login(request: StarletteRequest):
    oauth = request.app.state.oauth
   
    redirect_uri = GOOGLE_REDIRECT_URI
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/callback/google")
async def google_callback(request: StarletteRequest, db: AsyncSession = Depends(get_db)):
    oauth = request.app.state.oauth
    token = await oauth.google.authorize_access_token(request)
    print("GOOGLE TOKEN:", token)
    user_info = token.get("userinfo")
    if not user_info:
        # fallback: parse id_token if userinfo is missing
        user_info = await oauth.google.parse_id_token(request, token)
    if not user_info or 'email' not in user_info:
        raise HTTPException(status_code=400, detail="Google authentication failed")
    # Check if user exists
    result = await db.execute(select(User).where(User.email == user_info['email']))
    db_user = result.scalar_one_or_none()
    if not db_user:
        # Register new user
        db_user = User(
            email=user_info['email'],
            full_name=user_info.get('name'),
            google_id=user_info.get('sub')
        )
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
    # Issue JWT
    access_token = create_access_token({"sub": str(db_user.id), "email": db_user.email})
    response = RedirectResponse(url="http://localhost:3000/profile")
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False  # Set to True in production
    )
    return response

@router.get("/me", response_model=UserResponse)
async def get_me(
    access_token: Optional[str] = Cookie(None),
    db: AsyncSession = Depends(get_db)
):
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if not SECRET_KEY:
        raise HTTPException(status_code=500, detail="Server misconfiguration")
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str = payload.get("sub")
        if user_id_str is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = int(user_id_str)
    except (JWTError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid token")
    result = await db.execute(select(User).where(User.id == user_id))
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user 