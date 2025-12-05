import uuid
from datetime import timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select, SQLModel
from pydantic import Field, EmailStr, validator
import re

from database import get_session
from models.user import User
from security import create_access_token, get_password_hash, verify_password
from security import ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter(prefix="/auth", tags=["Authentication"])

class UserRegistration(SQLModel):
    username: str = Field(..., min_length=3, max_length=20, pattern="^[a-zA-Z0-9]+$")
    email: EmailStr = Field(...)
    password: str = Field(..., min_length=8)

    @validator('password')
    def password_complexity(cls, v):
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain a lowercase letter")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain an uppercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain a digit")
        if not re.search(r"[@$!%*?&]", v):
            raise ValueError("Password must contain a special character (@$!%*?&)")
        return v

class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"

@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistration, session: Session = Depends(get_session)):
    # Check if username or email already exists
    existing_user = session.exec(
        select(User).where(
            (User.username == user_data.username) | (User.email == user_data.email)
        )
    ).first()

    if existing_user:
        if existing_user.username == user_data.username:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already registered",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )

    hashed_password = get_password_hash(user_data.password)
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

class UserLogin(SQLModel):
    username: str = Field(..., min_length=3, max_length=20, pattern="^[a-zA-Z0-9]+$")
    password: str = Field(..., min_length=8) # Password validation will be done by verify_password

@router.post("/login", response_model=Token)
async def login_for_access_token(
    user_data: UserLogin, session: Session = Depends(get_session)
):
    user = session.exec(select(User).where(User.username == user_data.username)).first()

    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}