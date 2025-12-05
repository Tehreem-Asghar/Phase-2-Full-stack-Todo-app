import os
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from fastapi import HTTPException, status

# Password hashing utilities
from passlib.context import CryptContext

# Use pbkdf2_sha256 instead of bcrypt - more reliable and no 72-byte limit
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# JWT specific configurations
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # For example

if not SECRET_KEY or not ALGORITHM:
    # Fallback for local development if .env is not sourced
    # In production, these must be set
    SECRET_KEY = "supersecretkey"
    ALGORITHM = "HS256"
    #raise ValueError("SECRET_KEY and ALGORITHM environment variables must be set")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str, credentials_exception: HTTPException):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        return user_id
    except JWTError:
        raise credentials_exception
