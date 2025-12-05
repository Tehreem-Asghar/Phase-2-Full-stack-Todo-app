import uuid
from typing import Generator
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select
from database import get_session
from models.user import User
from security import verify_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

async def get_current_user(
    session: Session = Depends(get_session),
    token: str = Depends(oauth2_scheme)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    user_id_str = verify_token(token, credentials_exception)
    
    try:
        user_id_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise credentials_exception
    
    user = session.exec(select(User).where(User.id == user_id_uuid)).first()
    if user is None:
        raise credentials_exception
    return user